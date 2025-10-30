<?php

namespace Shokanshi\SingpassMyInfo\Services\Socialites;

use Exception;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
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
use Shokanshi\SingpassMyInfo\Exceptions\JwkInvalidException;
use Shokanshi\SingpassMyInfo\Exceptions\JwksInvalidException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtDecodeFailedException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtPayloadException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassJwksException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassPrivateKeyMissingException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassTokenException;
use stdClass;
use Symfony\Component\Clock\NativeClock;

final class SingpassProvider extends AbstractProvider implements ProviderInterface
{
    use Conditionable;

    protected ?JWKSet $signingJwks = null;

    protected ?JWKSet $decryptionJwks = null;

    /**
     * Create a new provider instance.
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @param  string  $redirectUrl
     * @param  array<string, string>  $guzzle
     * @return void
     */
    public function __construct(Request $request, $clientId, $clientSecret, $redirectUrl, $guzzle = [])
    {
        // Singpass uses pkce
        $this->enablePKCE();

        parent::__construct($request, $clientId, $clientSecret, $redirectUrl, $guzzle);
    }

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
     * This method is similar to addSigningKey() except that it accepts a json encoded jwk
     */
    public function addSigningKeyFromJsonObject(
        #[SensitiveParameter]
        string $json): self
    {
        $jwk = JWKFactory::createFromJsonObject($json);

        // TODO jwk could also be jwkset so it will be good to handle both

        if (! ($jwk instanceof JWK)) {
            throw new JwkInvalidException;
        }

        if (! $this->signingJwks) {
            $this->signingJwks = new JWKSet([$jwk]);

            return $this;
        }

        $this->signingJwks = $this->signingJwks->with($jwk);

        return $this;
    }

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application and
     * key rotation. In fact, it is recommended you use this function for assigning keys so that key rotation can be handled
     * seamlessly when you couple it with ->when()
     *
     * If this property is set, the private key file specified in .env will be ignored
     */
    public function addSigningKey(
        #[SensitiveParameter]
        string $keyContent,

        #[SensitiveParameter]
        ?string $passphrase = null): self
    {
        $jwk = JWKFactory::createFromKey($keyContent, $passphrase, [
            'use' => 'sig', 'alg' => 'ES256', 'kid' => hash('sha256', $keyContent),
        ]);

        if (! $this->signingJwks) {
            $this->signingJwks = new JWKSet([$jwk]);

            return $this;
        }

        $this->signingJwks = $this->signingJwks->with($jwk);

        return $this;
    }

    /**
     * This method is similar to addDecryptionKey() except that it accepts a json encoded jwk
     */
    public function addDecryptionKeyFromJsonObject(
        #[SensitiveParameter]
        string $json): self
    {
        $jwk = JWKFactory::createFromJsonObject($json);

        if (! ($jwk instanceof JWK)) {
            throw new JwkInvalidException;
        }

        if (! $this->decryptionJwks) {
            $this->decryptionJwks = new JWKSet([$jwk]);

            return $this;
        }

        $this->decryptionJwks = $this->decryptionJwks->with($jwk);

        return $this;
    }

    /**
     * Instead of using a pem file, you can set the content of the pem file here. Great for multitenancy application and
     * key rotation. In fact, it is recommended you use this function for assigning keys so that key rotation can be handled
     * seamlessly when you couple it with ->when()
     *
     * If this property is set, the private key file specified in .env will be ignored
     */
    public function addDecryptionKey(
        #[SensitiveParameter]
        string $keyContent,

        #[SensitiveParameter]
        ?string $passphrase = null): self
    {
        $jwk = JWKFactory::createFromKey($keyContent, $passphrase, [
            'use' => 'enc', 'alg' => 'ECDH-ES+A256KW', 'kid' => hash('sha256', $keyContent),
        ]);

        if (! $this->decryptionJwks) {
            $this->decryptionJwks = new JWKSet([$jwk]);

            return $this;
        }

        $this->decryptionJwks = $this->decryptionJwks->with($jwk);

        return $this;
    }

    public function setOpenIdDiscoveryUrl(string $url): self
    {
        config(['singpass-myinfo.openid_discovery_endpoint' => $url]);

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

        assert(is_string($config['authorization_endpoint']));

        // Singpass uses nonce
        return $this->with([
            'nonce' => (string) Str::uuid(),
        ])->buildAuthUrlFromBase($config['authorization_endpoint'], $state);
    }

    protected function getTokenUrl(): string
    {
        $config = $this->getOpenIDConfiguration();

        assert(is_string($config['token_endpoint']));

        return $config['token_endpoint'];
    }

    public function getAccessTokenResponse($code)
    {
        // construct token exchange request
        try {
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

            // Prove to PHPStan that $errorResponse is an array before logging it.
            assert(is_array($errorResponse));

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

        assert(is_array($response));

        if (isset($response['error']) && isset($response['error_description']) && is_string($response['error_description'])) {
            throw new SingpassTokenException(500, $response['error_description']);
        }

        assert(is_string(Arr::get($response, 'id_token')));

        $idTokenClaims = $this->decodeJWS(Arr::get($response, 'id_token'));
        $this->verifyIdToken($idTokenClaims);

        // return idTokenClaims as user for Singpass login
        if ($this->getScopes() === ['openid']) {
            $user = $idTokenClaims;
        } else {
            // Singpass MyInfo uses access_token for claims verification
            $accessToken = Arr::get($response, 'access_token');

            assert(is_string($accessToken));

            $accessTokenClaims = $this->decodeJWS($accessToken);

            $this->verifyAccessToken($accessTokenClaims);

            $user = $this->getUserByToken($accessToken);
        }

        return $this->userInstance($response, $user);
    }

    // A Client Assertion which replace the need of client secret
    private function generateClientAssertion(): string
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

        $signingJwk = null;

        // get the first jwk
        foreach ($this->getSigningJwks() as $jwk) {
            $signingJwk = $jwk;

            break;
        }

        if (! ($signingJwk instanceof JWK)) {
            throw new JwkInvalidException;
        }

        $payload = json_encode([
            'sub' => $this->clientId,
            'aud' => $config['issuer'],
            'iss' => $this->clientId,
            'iat' => $issuedAt->unix(),
            'exp' => $issuedAt->addMinutes(2)->unix(),
        ]);

        if (! $payload) {
            throw new JwtPayloadException;
        }

        // build jwt
        $jwt = $jwsBuilder->create()
            ->withPayload($payload) // insert claims data
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
     * Retrieves the user data from the MyInfo API using the provided token.
     *
     * @param  string  $token  The access token from Singpass.
     * @return array<string, mixed> The user's data as an associative array.
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
            $json = json_encode($jws);

            if ($json) {
                $result = json_decode($json, true);

                assert(is_array($result));

                // This PHPDoc comment tells PHPStan to treat $result as an array with string keys.
                /** @var array<string, mixed> $result */
                return $result;
            }
        }

        abort(Response::HTTP_BAD_REQUEST, 'Unable to decrypt JWE');
    }

    /**
     * Decodes and verifies the ID Token JWS.
     *
     * @param  string  $idToken  The raw ID Token string.
     * @return array<string, mixed> The decoded payload claims.
     */
    private function decodeJWS(string $idToken): array
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
            /** @var JWKSet $jwks */
            $jwks = $this->getSingpassJwks();

            assert(is_string($kid) || is_int($kid));

            $key = JWKFactory::createFromKeySet($jwks, $kid);
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

        $payload = $jws->getPayload();

        // This assertion tells PHPStan that $payload cannot be null from this point on.
        assert($payload !== null);

        /** @var array<string, mixed> */
        $result = json_decode($payload, true);

        return $result;
    }

    /**
     * retrieve the jwks from Singpass
     */
    private function getSingpassJwks(): JWKSet
    {
        try {
            $config = $this->getOpenIDConfiguration();

            assert(is_string($config['jwks_uri']));

            $response = Http::get($config['jwks_uri'])->throwUnlessStatus(200)->body();

            return JWKSet::createFromJson($response);
        } catch (Exception) {
            throw new SingpassJwksException;
        }
    }

    /**
     * Verifies the ID token claims against the client ID.
     *
     * @param  array<string, mixed>  $claims  The JWT payload claims to verify.
     */
    private function verifyIdToken(array $claims): void
    {
        $this->checkClaims($claims, $this->clientId);
    }

    /**
     * Verifies the access token claims against the userinfo endpoint audience.
     *
     * @param  array<string, mixed>  $claims  The JWT payload claims to verify.
     */
    private function verifyAccessToken(array $claims): void
    {
        $config = $this->getOpenIDConfiguration();

        assert(is_string($config['userinfo_endpoint']));

        // set aud based on auth or MyInfo
        $this->checkClaims($claims, $config['userinfo_endpoint']);
    }

    /**
     * Checks the JWT claims against expected values.
     *
     * @param  array<string, mixed>  $claims  The JWT payload claims to validate.
     * @param  string  $audience  The expected audience claim value.
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

    private function decryptJWE(string $idToken): ?string
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
        if ($decrypter->decryptUsingKeySet($jwe, $this->getDecryptionJwks(), 0)) {
            return $jwe->getPayload();
        }

        return null;
    }

    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param  array<string, mixed>  $user
     * @return User
     */
    protected function mapUserToObject($user)
    {
        assert(is_string($user['sub']));

        $name = '';
        $email = '';

        // if (array_key_exists('name', $user) && is_array($user['name'])) {
        if (isset($user['name']) && is_array($user['name'])) {
            $name = $user['name']['value'];
        }

        if (isset($user['email']) && is_array($user['email'])) {
            $email = $user['email']['value'];
        }

        $parseUserData = $this->parseUser($user['sub']);

        $user['id'] = $parseUserData['u'] ?? '';

        return (new User)->setRaw($user)->map([
            'id' => $user['id'],
            'name' => $name,
            'email' => $email,
        ]);
    }

    /**
     * Split the JWT claims sub and convert to a dictionary type
     *
     * @return array<string, mixed>
     */
    private function parseUser(string $content): array
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
     * @return array<string, mixed>
     *
     * @throws GuzzleException
     */
    public function getOpenIDConfiguration(): array
    {
        if (Cache::has('singpassOpenIDConfig')) {
            /** @var array<string, mixed> */
            return Cache::get('singpassOpenIDConfig');
        }

        assert(is_string(config('singpass-myinfo.openid_discovery_endpoint')));

        $response = $this->getHttpClient()->get(config('singpass-myinfo.openid_discovery_endpoint'), [
            'headers' => ['Accept' => 'application/json'],
        ]);
        $openIDConfig = json_decode($response->getBody(), true);

        Cache::put('singpassOpenIDConfig', $openIDConfig, now()->addHour());

        /** @var array<string, mixed> */
        return $openIDConfig;
    }

    private function verifyTokenSignature(string $token): stdClass|bool
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

        if (! $isVerified) {
            return false;
        }

        $payload = $jws->getPayload();

        // This assertion tells PHPStan that $payload cannot be null from this point on.
        assert($payload !== null);

        $result = json_decode($payload);

        assert(($result instanceof stdClass) || is_bool($result));

        return $result;
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

            assert(is_string($config['jwks_uri']));

            $response = $this->getHttpClient()->get($config['jwks_uri'], [
                'headers' => ['Accept' => 'application/json',
                ]]);

            $singpassJWKS = $response->getBody()->getContents();

            $jwks = JWKSet::createFromJson($singpassJWKS);

            // select Signature key
            $jwk = $jwks->selectKey('sig');

            // This assertion tells PHPStan that $jwk cannot be null from this point on.
            assert($jwk !== null);

            return $jwk;

        } catch (ServerException $e) {
            $errorResponse = $e->getResponse()->getBody()->getContents();
            $errorResponse = json_decode($errorResponse, true);

            // Prove to PHPStan that $errorResponse is an array before logging it.
            assert(is_array($errorResponse));

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

            assert(is_string($config['userinfo_endpoint']));

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

            // Prove to PHPStan that $errorResponse is an array before logging it.
            assert(is_array($errorResponse));

            Log::error('Unable to retrieve Singpass JWKS', $errorResponse);
            abort(Response::HTTP_BAD_GATEWAY, 'Unable to login using Singpass right now');
        }
    }

    /**
     * @throws JwksInvalidException
     */
    private function getSigningJwks(): JWKSet
    {
        // default to load key from .env if none is specified
        if (! $this->signingJwks) {
            $file = config('singpass-myinfo.signing_private_key_file');
            $passphrase = config('singpass-myinfo.signing_private_key_file_passphrase');

            assert(is_string($file));
            assert(is_null($passphrase) || is_string($passphrase));

            $this->addSigningKey($this->getPrivateKeyFileContent($file), $passphrase);
        }

        if (! $this->signingJwks) {
            throw new JwksInvalidException(500, 'Signing JWKS missing');
        }

        return $this->signingJwks;
    }

    /**
     * @throws JwksInvalidException
     */
    private function getDecryptionJwks(): JWKSet
    {
        // default to load key from .env if none is specified
        if (! $this->decryptionJwks) {
            $file = config('singpass-myinfo.decryption_private_key_file');
            $passphrase = config('singpass-myinfo.decryption_private_key_passphrase');

            assert(is_string($file));
            assert(is_null($passphrase) || is_string($passphrase));

            $this->addDecryptionKey($this->getPrivateKeyFileContent($file), $passphrase);
        }

        if (! $this->decryptionJwks) {
            throw new JwksInvalidException(500, 'Decryption JWKS missing');
        }

        return $this->decryptionJwks;
    }

    /**
     * Generates the JWKS structure for the Singpass Portal.
     *
     * @return array{keys: array<JWK>}
     */
    public function generateJwksForSingpassPortal(): array
    {
        $jwks = ['keys' => []];

        /** @var JWK $key */
        foreach ($this->getSigningJwks() as $key) {
            $jwks['keys'][] = $key->toPublic();
        }

        /** @var JWK $key */
        foreach ($this->getDecryptionJwks() as $key) {
            $jwks['keys'][] = $key->toPublic();
        }

        return $jwks;
    }

    /**
     * @throws SingpassPrivateKeyMissingException
     */
    private function getPrivateKeyFileContent(string $file): string
    {
        if (! Storage::disk('local')->exists($file)) {
            throw new SingpassPrivateKeyMissingException(500, "Singpass private key file not found. Expected at: storage/app/{$file}");
        }

        $content = Storage::disk('local')->get($file);

        // This assertion tells PHPStan that $content cannot be null from this point on.
        assert($content !== null);

        return $content;
    }
}
