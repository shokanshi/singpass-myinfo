<?php

namespace Shokanshi\SingpassMyInfo\Services\Socialites;

use Exception;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use SensitiveParameter;
use Shokanshi\SingpassMyInfo\Exceptions\JwtDecodeFailedException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtPayloadException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassJwksException;
use stdClass;
use Symfony\Component\Clock\NativeClock;

class SingpassProvider extends AbstractProvider implements ProviderInterface
{
    protected string $clientPrivateKey = '';

    /**
     * You can directly update the client id bypassing config file. Great for multitenancy application
     */
    public function setClientId(string $clientId): self
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * You can directly update the redirect url bypassing config file. Great for multitenancy application
     */
    public function setRedirectUrl(string $redirectUrl): self
    {
        $this->redirectUrl = $redirectUrl;

        return $this;
    }

    public function setClientPrivateKeyPassphrase(
        #[SensitiveParameter]
        string $passphrase
    ): self {
        config(['singpass-myinfo.client_private_key_passphrase' => $passphrase]);

        return $this;
    }

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application
     * If this property is set, the private key file will be ignored
     */
    public function setClientPrivateKey(
        #[SensitiveParameter]
        string $clientPrivateKey
    ): self {
        $this->clientPrivateKey = $clientPrivateKey;

        return $this;
    }

    public function setClientPrivateKeyFile(
        #[SensitiveParameter]
        string $file
    ): self {
        config(['singpass-myinfo.client_private_key_file' => $file]);

        return $this;
    }

    public function setDomain(string $domain): self
    {
        config(['singpass-myinfo.domain' => $domain]);

        return $this;
    }

    public function setOpenIdDiscoveryUrl(string $url): self
    {
        config(['singpass-myinfo.openid_discovery_url' => $url]);

        return $this;
    }

    // Return an Authorization Endpoint that will be used to redirect to Singpass
    protected function getAuthUrl($state)
    {
        $config = $this->getOpenIDConfiguration();

        if ($this->isStateless()) {
            return '';
        }

        // Singpass uses space as scope separator
        $this->scopeSeparator = ' ';

        // Singpass uses pkce and nonce
        return $this->enablePKCE()->with([
            'nonce' => (string) Str::uuid(),
        ])->buildAuthUrlFromBase($config['authorization_endpoint'], $state);
    }

    protected function getTokenUrl()
    {
        $config = $this->getOpenIDConfiguration();

        return $config['token_endpoint'];
    }

    public function getAccessTokenResponse($code)
    {
        // construct token exchange request
        try {
            // Singpass uses pkce
            $this->enablePKCE();

            $clientAssertion = $this->generateClientAssertion();

            $response = Http::bodyFormat('form_params')
                ->contentType('application/x-www-form-urlencoded; charset=ISO-8859-1')
                ->post($this->getTokenUrl(), [
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'code' => $code,
                    'client_id' => $this->clientId,
                    'grant_type' => 'authorization_code',
                    'redirect_uri' => $this->redirectUrl,
                    'client_assertion' => $clientAssertion,
                    'code_verifier' => $this->request->session()->get('code_verifier'),
                ]);

            $responseBody = json_decode($response->getBody(), true);

            return $responseBody;
        } catch (ClientException $requestException) {
            Log::error($requestException->getMessage());
            abort(Response::HTTP_BAD_REQUEST, 'Invalid parameter pass in while requesting Singpass token');
        } catch (ServerException $guzzleException) {
            // catch if there any internal server error occurred at singpass
            $errorResponse = $guzzleException->getResponse()->getBody()->getContents();
            $errorResponse = json_decode($errorResponse, true);
            Log::error('Singpass Internal Server Error', $errorResponse);
            abort(Response::HTTP_BAD_GATEWAY, 'Unable to login using Singpass right now');
        }

    }

    // A Client Assertion which replace the need of client secret
    private function generateClientAssertion()
    {
        $config = $this->getOpenIDConfiguration();

        $signingJwk = $this->getSigningPrivateJwk();

        $algorithmFactory = new AlgorithmManagerFactory;

        // initiate the algorithm aliases
        $algorithmFactory->add('ES256', new ES256);
        $algorithmFactory->add('ES384', new ES384);
        $algorithmFactory->add('ES512', new ES512);

        // load all the support signature algorithm based on singpass API openid configuration
        $algorithmFactory->create($config['token_endpoint_auth_signing_alg_values_supported']);

        $algorithmManager = new AlgorithmManager($algorithmFactory->all());

        $jwsBuilder = new JWSBuilder($algorithmManager);

        // JWT issue timestamp
        $issuedAt = now();

        // build jwt
        $jwt = $jwsBuilder->create()
            ->withPayload(json_encode([
                'sub' => $this->clientId,
                'aud' => $config['issuer'],
                'iss' => $this->clientId,
                'iat' => $issuedAt->unix(),
                'exp' => $issuedAt->addMinutes(2)->unix(),
            ])) // insert claims data
            ->addSignature($signingJwk, ['typ' => 'JWT', 'alg' => 'ES256']) // sign it and add the JWS protected header
            ->build();
        $serializer = new CompactSerializer; // The serializer

        // generate base64 encoded JWT
        $clientAssertion = $serializer->serialize($jwt, 0);

        return $clientAssertion;
    }

    /**
     * The token which is a JWE that need to be decrypted to retrieve MyInfo
     */
    protected function getUserByToken($token): array
    {
        // This is a JWS, use the new verification logic
        Log::info('Processing JWS token.');

        $payload = $this->decodeJWS($token);

        // Verify the signature using Singpass's public key
        $this->verifyPayload($payload);

        $jwe = $this->getMyInfoJWE($token);

        // decrypt the JWE
        $content = $this->decryptJWE($jwe);

        if (! is_null($content)) {
            // verify the content of JWT
            $jws = $this->verifyTokenSignature($content);
            if (! $jws) {
                // abort if signature check failed
                abort(Response::HTTP_UNAUTHORIZED, 'Singpass Signature checking failed');
            }

            // convert stdClass to json string and then use json_decode to return it as an array
            return json_decode(json_encode($jws), true);
        }

        abort(Response::HTTP_BAD_REQUEST, 'Unable to decrypt JWE');
    }

    private function decodeJWS($idToken)
    {
        $algorithmManager = new AlgorithmManager([
            new ES256,
        ]);

        $jwsVerifier = new JWSVerifier($algorithmManager);

        $serializerManager = new JWSSerializerManager([
            new CompactSerializer,
        ]);

        try {
            $kid = $serializerManager->unserialize($idToken)->getSignature(0)->getProtectedHeaderParameter('kid');
        } catch (InvalidArgumentException) {
            throw new JwtDecodeFailedException(500, 'JWT supplied is invalid.');
        }

        try {
            $jwksKeyset = $this->getSingpassJwks();
            $key = JWKFactory::createFromKeySet($jwksKeyset, $kid);
        } catch (InvalidArgumentException) {
            throw new JwtDecodeFailedException(500, 'Keyset does not contain KID from JWT.');
        }

        $headerCheckerManager = new HeaderCheckerManager([
            new AlgorithmChecker(['ES256']),
        ], [
            new JWSTokenSupport,
        ]);

        $jwsLoader = new JWSLoader($serializerManager, $jwsVerifier, $headerCheckerManager);

        $jws = $jwsLoader->loadAndVerifyWithKey($idToken, $key, $signature);

        return json_decode($jws->getPayload(), true);
    }

    /**
     * retrieve the jwks from Singpass
     */
    private function getSingpassJwks(): JWKSet
    {
        try {
            $config = $this->getOpenIDConfiguration();

            $response = Http::get($config['jwks_uri'])->throwUnlessStatus(200)->body();

            return JWKSet::createFromJson($response);
        } catch (Exception) {
            throw new SingpassJwksException;
        }
    }

    /**
     * Verify the payload to ensure it is valid
     */
    private function verifyPayload(array $payload): void
    {
        $clock = new NativeClock;

        $config = $this->getOpenIDConfiguration();
        $aud = $config['userinfo_endpoint'];

        $claimCheckerManager = new ClaimCheckerManager([
            new AudienceChecker($aud),
            new IssuedAtChecker($clock, 5),
            new ExpirationTimeChecker($clock, 5),
            new IssuerChecker([config('singpass-myinfo.domain')]),
        ]);

        try {
            $claimCheckerManager->check($payload);
        } catch (InvalidClaimException $exception) {
            throw new JwtPayloadException(400, $exception->getMessage());
        }
    }

    private function decryptJWE($idToken)
    {
        $config = $this->getOpenIDConfiguration();

        $keyEncryptionsAlgo = new AlgorithmManagerFactory;

        // create algorithm alias for token encryption that might used by singpass
        $keyEncryptionsAlgo->add('A256GCM', new A256GCM);
        $keyEncryptionsAlgo->add('ECDH-ES+A256KW', new ECDHESA256KW);
        $keyEncryptionsAlgo->add('ECDH-ES+A192KW', new ECDHESA192KW);
        $keyEncryptionsAlgo->add('ECDH-ES+A128KW', new ECDHESA128KW);
        $keyEncryptionsAlgo->add('RSA-OAEP-256', new RSAOAEP256);
        $keyEncryptionsAlgo->create($config['id_token_encryption_alg_values_supported'] ?? []);

        // create algorithm alias for content encryption that used by singpass based on openid configuration
        $contentEncryptionAlgo = new AlgorithmManagerFactory;
        $contentEncryptionAlgo->add('A256CBC-HS512', new A256CBCHS512);

        $contentEncryptionAlgo->create($config['id_token_encryption_enc_values_supported'] ?? []);

        $keyEncryptionAlgorithmManager = new AlgorithmManager($keyEncryptionsAlgo->all());
        $contentEncryptionAlgorithmManager = new AlgorithmManager($contentEncryptionAlgo->all());

        // create a JWE decrypter
        $decrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
        );

        $decryptionJwk = $this->getDecryptionPrivateJwk();

        $serializerManager = new JWESerializerManager([new \Jose\Component\Encryption\Serializer\CompactSerializer]);
        $jwe = $serializerManager->unserialize($idToken);

        // if decryption is success return the decrypted payload
        if ($decrypter->decryptUsingKey($jwe, $decryptionJwk, 0)) {
            return $jwe->getPayload();
        }

        return null;
    }

    /**
     * Convert the JWT user claims, separated comma user info to array
     *
     * @return User
     */
    protected function mapUserToObject($user)
    {
        $parseUserData = $this->parseUser($user['sub']);

        $user['id'] = $parseUserData['u'] ?? '';

        return (new User)->setRaw($user)->map([
            'id' => $user['id'],
            'name' => $user['name']['value'] ?? '',
            'email' => $user['email']['value'] ?? '',
        ]);
    }

    /**
     * Split the JWT claims sub and convert to a dictionary type
     *
     * @return array
     */
    private function parseUser($content)
    {
        $processedData = [];
        $dataRecord = explode(',', $content);
        foreach ($dataRecord as $record) {
            $data = explode('=', $record);
            $processedData[$data[0]] = $data[1] ?? '';
        }

        return $processedData;
    }

    /**
     * Retrieve Singpass API OpenID configuration
     *
     * @return mixed
     *
     * @throws GuzzleException
     */
    public function getOpenIDConfiguration()
    {
        if (Cache::has('singpassOpenIDConfig')) {
            return Cache::get('singpassOpenIDConfig');
        }
        $response = $this->getHttpClient()->get(config('singpass-myinfo.openid_discovery_url'), [
            'headers' => ['Accept' => 'application/json'],
        ]);
        $openIDConfig = json_decode($response->getBody(), true);

        Cache::put('singpassOpenIDConfig', $openIDConfig, now()->addHour());

        return $openIDConfig;
    }

    private function verifyTokenSignature($token): stdClass|bool
    {
        $config = $this->getOpenIDConfiguration();

        // load Singpass JWKS
        $singpassJWKS = $this->retrieveSingpassVerificationKey();
        $jwks = JWKSet::createFromJson($singpassJWKS);

        // select Signature key
        $verificationKey = $jwks->selectKey('sig');

        $signatureAlgo = new AlgorithmManagerFactory;
        $signatureAlgo->add('ES256', new ES256);
        $signatureAlgo->create($config['id_token_signing_alg_values_supported'] ?? []);

        $signatureAlgoManager = new AlgorithmManager($signatureAlgo->all());
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer,
        ]);

        $jwsVerifier = new JWSVerifier($signatureAlgoManager);

        $jws = $serializerManager->unserialize($token);
        $isVerified = $jwsVerifier->verifyWithKey($jws, $verificationKey, 0);

        return $isVerified ? json_decode($jws->getPayload()) : false;
    }

    /**
     * Load the Singpass API verification key from Singpass JWKS endpoints
     *
     * @throws GuzzleException
     */
    private function retrieveSingpassVerificationKey(): string
    {
        $config = $this->getOpenIDConfiguration();
        try {
            $response = $this->getHttpClient()->get($config['jwks_uri'], [
                'headers' => ['Accept' => 'application/json',
                ]]);

            return $response->getBody()->getContents();

        } catch (ServerException $e) {
            $errorResponse = $e->getResponse()->getBody()->getContents();
            $errorResponse = json_decode($errorResponse, true);
            Log::error('Unable to retrieve Singpass JWKS', $errorResponse);
            abort(Response::HTTP_BAD_GATEWAY, 'Unable to login using Singpass right now');
        }
    }

    /**
     * Retrieve MyInfo JWE from Singpass
     */
    private function getMyInfoJWE(string $token): string
    {
        try {
            $config = $this->getOpenIDConfiguration();

            $response = $this->getHttpClient()
                ->get($config['userinfo_endpoint'], [
                    'headers' => [
                        'Content-Type' => 'application/x-www-form-urlencoded; charset=ISO-8859-1',
                        'Authorization' => "Bearer {$token}",
                    ]]);

            return $response->getBody()->getContents();

        } catch (ServerException $e) {
            $errorResponse = $e->getResponse()->getBody()->getContents();
            $errorResponse = json_decode($errorResponse, true);
            Log::error('Unable to retrieve Singpass JWKS', $errorResponse);
            abort(Response::HTTP_BAD_GATEWAY, 'Unable to login using Singpass right now');
        }
    }

    private function getSigningPrivateJwk(): JWK
    {
        return $this->getClientPrivateJwk([
            'use' => 'sig', 'alg' => 'ES256', 'kid' => $this->generateKidForSingpass('sig-key-'),
        ]);
    }

    private function getDecryptionPrivateJwk(): JWK
    {
        return $this->getClientPrivateJwk([
            'use' => 'enc', 'alg' => 'ECDH-ES+A256KW', 'kid' => $this->generateKidForSingpass('enc-key-'),
        ]);
    }

    private function getClientPrivateJwk(array $additionalValues): JWK
    {
        return JWKFactory::createFromKey($this->getClientPrivateKey(), config('singpass-myinfo.client_private_key_passphrase'), $additionalValues);
    }

    /**
     * Singpass checks kid for client key rotation so we will use the hash of the client private key to generate kid
     */
    private function generateKidForSingpass(string $kidPrefix): string
    {
        return $kidPrefix.hash('sha256', $this->getClientPrivateKey());
    }

    private function getClientPrivateKey(): string
    {
        if ($this->clientPrivateKey) {
            return $this->clientPrivateKey;
        }

        return $this->clientPrivateKey = file_get_contents('file://'.base_path(config('singpass-myinfo.client_private_key_file')));
    }

    public function generateJwksForSingpassPortal(): array
    {
        $jwks['keys'][] = $this->getSigningPrivateJwk()->toPublic();
        $jwks['keys'][] = $this->getDecryptionPrivateJwk()->toPublic();

        return $jwks;
    }
}
