<?php

namespace Shokanshi\SingpassMyInfo\Services\Socialites;

use Exception;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Illuminate\Http\Response;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Support\Traits\Conditionable;
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
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
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
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use SensitiveParameter;
use Shokanshi\SingpassMyInfo\Dtos\PrivateKeyData;
use Shokanshi\SingpassMyInfo\Exceptions\JwksInvalidException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtDecodeFailedException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtPayloadException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassJwksException;
use Spatie\LaravelData\Attributes\Hidden;
use Spatie\LaravelData\DataCollection;
use stdClass;
use Symfony\Component\Clock\NativeClock;

final class SingpassProvider extends AbstractProvider implements ProviderInterface
{
    use Conditionable;

    #[Hidden]
    protected ?DataCollection $signingPrivateKeys = null;

    #[Hidden]
    protected ?DataCollection $decryptionPrivateKeys = null;

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

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application and
     * key rotation.
     *
     * If this property is set, the private key file specified in .env will be ignored
     */
    public function setSigningPrivateKeys(
        #[SensitiveParameter]
        array $keys
    ): self {
        $this->signingPrivateKeys = new DataCollection(PrivateKeyData::class, $keys);

        return $this;
    }

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application and
     * key rotation.
     *
     * If this property is set, the private key file specified in .env will be ignored
     */
    public function setDecryptionPrivateKeys(
        #[SensitiveParameter]
        array $keys
    ): self {
        $this->decryptionPrivateKeys = new DataCollection(PrivateKeyData::class, $keys);

        return $this;
    }

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application and
     * key rotation. In fact, it is recommended you use this function for assigning keys so that key rotation can be handled
     * seamlessly when you couple it with ->when()
     *
     * If this property is set, the private key file specified in .env will be ignored
     */
    public function addSigningPrivateKey(
        #[SensitiveParameter]
        array $key
    ): self {
        if (! $this->signingPrivateKeys) {
            $this->signingPrivateKeys = new DataCollection(PrivateKeyData::class, [$key]);

            return $this;
        }

        $keys = $this->signingPrivateKeys->toCollection();
        $this->signingPrivateKeys = new DataCollection(PrivateKeyData::class, $keys->push($key));

        return $this;
    }

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application and
     * key rotation. In fact, it is recommended you use this function for assigning keys so that key rotation can be handled
     * seamlessly when you couple it with ->when()
     *
     * If this property is set, the private key file specified in .env will be ignored
     */
    public function addDecryptionPrivateKey(
        #[SensitiveParameter]
        array $key
    ): self {
        if (! $this->decryptionPrivateKeys) {
            $this->decryptionPrivateKeys = new DataCollection(PrivateKeyData::class, [$key]);

            return $this;
        }

        $keys = $this->decryptionPrivateKeys->toCollection();
        $this->decryptionPrivateKeys = new DataCollection(PrivateKeyData::class, $keys->push($key));

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
        if ($this->isStateless()) {
            return '';
        }

        $config = $this->getOpenIDConfiguration();

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

            return json_decode($response->getBody(), true);

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

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $idTokenClaims = $this->decodeJWS(Arr::get($response, 'id_token'));
        $this->verifyIdToken($idTokenClaims);

        // return idTokenClaims as user for Singpass login
        if ($this->getScopes() === ['openid']) {
            $user = $idTokenClaims;
        } else {
            // Singpass MyInfo uses access_token for claims verification
            $accessToken = Arr::get($response, 'access_token');

            $accessTokenClaims = $this->decodeJWS($accessToken);

            $this->verifyAccessToken($accessTokenClaims);

            $user = $this->getUserByToken($accessToken);
        }

        return $this->userInstance($response, $user);
    }

    // A Client Assertion which replace the need of client secret
    private function generateClientAssertion()
    {
        $config = $this->getOpenIDConfiguration();

        $algorithmManager = new AlgorithmManager([
            new ES256,
            new ES384,
            new ES512,
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        // JWT issue timestamp
        $issuedAt = now();

        // get the first jwk
        $signingJwk = $this->getSigningPrivateJwks()->getIterator()->current();

        if (! $signingJwk) {
            throw new JwksInvalidException;
        }

        // build jwt
        $jwt = $jwsBuilder->create()
            ->withPayload(json_encode([
                'sub' => $this->clientId,
                'aud' => $config['issuer'],
                'iss' => $this->clientId,
                'iat' => $issuedAt->unix(),
                'exp' => $issuedAt->addMinutes(2)->unix(),
            ])) // insert claims data
            ->addSignature($signingJwk, [
                'typ' => 'JWT',
                'alg' => 'ES256',
                'kid' => $signingJwk->get('kid'),
            ]) // sign it and add the JWS protected header
            ->build();

        $serializer = new CompactSerializer; // The serializer

        // generate base64 encoded JWT client assertion
        return $serializer->serialize($jwt);
    }

    /**
     * The token which is a JWE that need to be decrypted to retrieve Login / MyInfo
     */
    protected function getUserByToken($token): array
    {
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

    private function verifyIdToken(array $claims): void
    {
        $this->checkClaims($claims, $this->clientId);
    }

    private function verifyAccessToken(array $claims): void
    {
        $config = $this->getOpenIDConfiguration();

        // set aud based on auth or MyInfo
        $audience = $config['userinfo_endpoint'];

        $this->checkClaims($claims, $audience);
    }

    /**
     * Verify the payload to ensure it is valid
     */
    private function checkClaims(array $claims, string $audience): void
    {
        $clock = new NativeClock;

        $config = $this->getOpenIDConfiguration();

        $claimCheckerManager = new ClaimCheckerManager([
            new AudienceChecker($audience),
            new IssuedAtChecker($clock, 5),
            new ExpirationTimeChecker($clock, 5),
            new IssuerChecker([$config['issuer']]),
        ]);

        try {
            $claimCheckerManager->check($claims);
        } catch (InvalidClaimException $exception) {
            throw new JwtPayloadException(400, $exception->getMessage());
        }
    }

    private function decryptJWE($idToken)
    {
        $algorithmManager = new AlgorithmManager([
            new A256GCM,
            new ECDHESA128KW,
            new ECDHESA192KW,
            new ECDHESA256KW,
        ]);

        $decrypter = new JWEDecrypter($algorithmManager);

        $serializerManager = new JWESerializerManager([new \Jose\Component\Encryption\Serializer\CompactSerializer]);
        $jwe = $serializerManager->unserialize($idToken);

        // if decryption is success return the decrypted payload
        if ($decrypter->decryptUsingKeySet($jwe, $this->getDecryptionPrivateJwks(), 0)) {
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
        $signatureAlgoManager = new AlgorithmManager([
            new ES256,
        ]);

        $serializerManager = new JWSSerializerManager([
            new CompactSerializer,
        ]);

        $jwsVerifier = new JWSVerifier($signatureAlgoManager);

        // load Singpass JWKS signature key
        $verificationKey = $this->retrieveSingpassVerificationKey();

        $jws = $serializerManager->unserialize($token);
        $isVerified = $jwsVerifier->verifyWithKey($jws, $verificationKey, 0);

        return $isVerified ? json_decode($jws->getPayload()) : false;
    }

    /**
     * Load the Singpass API verification key from Singpass JWKS endpoints
     *
     * @throws GuzzleException
     */
    private function retrieveSingpassVerificationKey(): JWK
    {
        try {
            $config = $this->getOpenIDConfiguration();

            $response = $this->getHttpClient()->get($config['jwks_uri'], [
                'headers' => ['Accept' => 'application/json',
                ]]);

            $singpassJWKS = $response->getBody()->getContents();

            $jwks = JWKSet::createFromJson($singpassJWKS);

            // select Signature key
            return $jwks->selectKey('sig');

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

    public function getSigningPrivateJwks(): JWKSet
    {
        // default to load key from .env if none is specified
        if (! $this->signingPrivateKeys) {
            $this->setSigningPrivateKeys([
                [
                    'keyContent' => file_get_contents('file://'.base_path(config('singpass-myinfo.signing_private_key_file'))),
                    'passphrase' => config('singpass-myinfo.signing_private_key_file_passphrase'),
                ],
            ]);
        }

        $jwks = [];
        foreach ($this->signingPrivateKeys as $key) {
            $jwks[] = JWKFactory::createFromKey($key->keyContent, $key->passphrase, [
                'use' => 'sig', 'alg' => 'ES256', 'kid' => $key->keyId(),
            ]);
        }

        return new JWKSet($jwks);
    }

    public function getDecryptionPrivateJwks(): JWKSet
    {
        // default to load key from .env if none is specified
        if (! $this->decryptionPrivateKeys) {
            $this->setDecryptionPrivateKeys([
                [
                    'keyContent' => file_get_contents('file://'.base_path(config('singpass-myinfo.decryption_private_key_file'))),
                    'passphrase' => config('singpass-myinfo.decryption_private_key_passphrase'),
                ],
            ]);
        }

        $jwks = [];
        foreach ($this->decryptionPrivateKeys as $key) {
            $jwks[] = JWKFactory::createFromKey($key->keyContent, $key->passphrase, [
                'use' => 'enc', 'alg' => 'ECDH-ES+A256KW', 'kid' => $key->keyId(),
            ]);
        }

        return new JWKSet($jwks);
    }

    public function generateJwksForSingpassPortal(): array
    {
        foreach ($this->getSigningPrivateJwks() as $key) {
            $jwks['keys'][] = $key->toPublic();
        }

        foreach ($this->getDecryptionPrivateJwks() as $key) {
            $jwks['keys'][] = $key->toPublic();
        }

        return $jwks;
    }
}
