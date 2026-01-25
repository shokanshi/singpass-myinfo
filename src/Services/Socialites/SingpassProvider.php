<?php

namespace Shokanshi\SingpassMyInfo\Services\Socialites;

use Exception;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Support\Traits\Conditionable;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
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
use Shokanshi\SingpassMyInfo\Exceptions\JweInvalidException;
use Shokanshi\SingpassMyInfo\Exceptions\JwkInvalidException;
use Shokanshi\SingpassMyInfo\Exceptions\JwksInvalidException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtDecodeFailedException;
use Shokanshi\SingpassMyInfo\Exceptions\JwtPayloadException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassJwksException;
use Shokanshi\SingpassMyInfo\Exceptions\SingpassMissingRedirectUrlException;
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

        // remove the need to define SINGPASS_REDIRECT_URI in .env file for login and callback endpoint
        if (match (Route::currentRouteName()) {
            'singpass.callback',
            'singpass.login', => true,

            // jwks endpoint does not use redirectUrl
            default => false
        }) {
            $redirectUrl = route('singpass.callback', $request->route()->parameters ?? []);
        }

        parent::__construct($request, $clientId, $clientSecret, $redirectUrl, $guzzle);
    }

    /**
     * MARK: setClientId
     * You can directly update the client id bypassing config file. Great for multitenancy application
     */
    public function setClientId(string $clientId): self
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * MARK: setRedirectUrl
     * You can directly update the redirect url bypassing config file. Great for multitenancy application
     */
    public function setRedirectUrl(string $redirectUrl): self
    {
        $this->redirectUrl = $redirectUrl;

        return $this;
    }

    /**
     * MARK: addSigningKeyFromJsonObject
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
     * MARK: addSigningKey
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
     * MARK: addDecryptionKeyFromJsonObject
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
     * MARK: addDecryptionKey
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

    /**
     * MARK: setOpenIdDiscoveryUrl
     */
    public function setOpenIdDiscoveryUrl(string $url): self
    {
        config(['singpass-myinfo.openid_discovery_endpoint' => $url]);

        return $this;
    }

    /**
     * MARK: getAuthUrl
     * Return an Authorization Endpoint that will be used to redirect to Singpass
     */
    protected function getAuthUrl($state)
    {
        if ($this->isStateless()) {
            return '';
        }

        if (! $this->redirectUrl) {
            throw new SingpassMissingRedirectUrlException('Redirect url is missing', 400);
        }

        /** @var array<string, string> $config */
        $config = $this->getOpenIDConfiguration();

        // Singpass uses space as scope separator
        $this->scopeSeparator = ' ';

        /** @var string $clientAssertion */
        $clientAssertion = $this->generateClientAssertion();

        $dpopProof = $this->generateDPoPProof($config['pushed_authorization_request_endpoint']);

        /** @var array<string, string> $data */
        $data = $this->getCodeFields($state);
        $data['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $data['client_assertion'] = $clientAssertion;
        $data['nonce'] = (string) Str::uuid();

        $response = Http::bodyFormat('form_params')
            ->contentType('application/x-www-form-urlencoded')
            ->withHeader('DPoP', $dpopProof)
            ->post($config['pushed_authorization_request_endpoint'], $data);

        $result = json_decode($response->body(), true);

        assert(is_array($result));

        if ($response->failed()) {
            assert(is_string($result['error']));

            throw new SingpassPushedAuthorizationRequestException($this->getErrorDescription($result['error']), $response->status());
        }

        assert(is_string($result['request_uri']));

        $url = $config['authorization_endpoint'].'?'.http_build_query([
            'client_id' => $this->clientId,
            'request_uri' => $result['request_uri'],
        ], '', '&', $this->encodingType);

        return $url;
    }

    /**
     * MARK: getTokenUrl
     */
    protected function getTokenUrl(): string
    {
        $config = $this->getOpenIDConfiguration();

        assert(is_string($config['token_endpoint']));

        return $config['token_endpoint'];
    }

    /**
     * MARK: getAccessTokenResponse
     */
    public function getAccessTokenResponse($code)
    {
        // construct token exchange request
        $clientAssertion = $this->generateClientAssertion();

        $dpopProof = $this->generateDPoPProof($this->getTokenUrl());

        $response = Http::bodyFormat('form_params')
            ->contentType('application/x-www-form-urlencoded')
            ->withHeader('DPoP', $dpopProof)
            ->post($this->getTokenUrl(), [
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'code' => $code,
                'client_id' => $this->clientId,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->redirectUrl,
                'client_assertion' => $clientAssertion,
                'code_verifier' => $this->request->session()->get('code_verifier'),
            ]);

        $result = json_decode($response->body(), true);

        if ($response->failed()) {
            assert(is_array($result));
            assert(is_string($result['error']));

            throw new SingpassTokenException($this->getErrorDescription($result['error']), $response->status());
        }

        return $result;
    }

    /**
     * MARK: user
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        /** @var array<string, string> $response */
        $response = $this->getAccessTokenResponse($this->getCode());

        $token = '';

        if ($this->getScopes() === ['openid']) {
            // Singpass login uses id_token
            $token = Arr::get($response, 'id_token');

            assert(is_string($token));
        } else {
            // Singpass MyInfo uses access_token for claims verification
            $accessToken = Arr::get($response, 'access_token');

            assert(is_string($accessToken));

            $token = $this->getMyInfoJWE($accessToken);
        }

        $user = $this->getUserByToken($token);

        return $this->userInstance($response, $user);
    }

    /**
     * MARK: generateClientAssertion
     * A Client Assertion which replace the need of client secret
     */
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
            'jti' => (string) Str::uuid(),
        ]);

        assert(is_string($payload));

        // build jws
        $jws = $jwsBuilder->create()
            ->withPayload($payload) // insert claims data
            ->addSignature($signingJwk, [
                'typ' => 'JWT',
                'alg' => 'ES256',
                'kid' => $signingJwk->get('kid'),
            ]) // sign it and add the JWS protected header
            ->build();

        // serialize to compact format
        return (new CompactSerializer)->serialize($jws, 0);
    }

    private function generateDPoPProof(string $url, string $method = 'POST', ?string $accessToken = null): string
    {
        // $config = $this->getOpenIDConfiguration();

        $algorithmManager = new AlgorithmManager([
            new ES256,
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

        $claims = [
            'htm' => strtoupper($method),              // HTTP method: GET or POST
            'htu' => $url,  // Target URL (no query/fragment)
            'iat' => $issuedAt->unix(),          // Issued at (Unix timestamp in seconds)
            'exp' => $issuedAt->addMinutes(2)->unix(),          // Expiry (max 2 minutes after iat)
            'jti' => (string) Str::uuid(),     // Unique identifier (generate new for each request)
        ];

        if ($accessToken) {
            $claims['ath'] = $this->base64UrlEncode($accessToken); // Required only for /userinfo: SHA-256 hash of access token
        }

        $payload = json_encode($claims);

        $protectedHeader = [
            'typ' => 'dpop+jwt',
            'alg' => 'ES256',
            'jwk' => $signingJwk->toPublic()->all(),
        ];

        assert(is_string($payload));

        // create and sign jws
        $jws = $jwsBuilder->create()
            ->withPayload($payload) // insert claims data
            ->addSignature($signingJwk, $protectedHeader) // sign it and add the JWS protected header
            ->build();

        // serialize to compact format
        return (new CompactSerializer)->serialize($jws, 0);
    }

    /**
     * MARK: getUserByToken
     * Retrieves the user data from the MyInfo API using the provided token.
     *
     * @param  string  $token  The access token from Singpass.
     * @return array<string, mixed> The user's data as an associative array.
     */
    protected function getUserByToken($token): array
    {
        // decrypt the JWE
        /** @var ?string $content */
        $content = $this->decryptJWE($token);

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
                $claims = json_decode($json, true);

                assert(is_array($claims));

                // This PHPDoc comment tells PHPStan to treat $claims as an array with string keys.
                /** @var array<string, mixed> $claims */
                return $claims;
            }
        }

        abort(Response::HTTP_BAD_REQUEST, 'Unable to decrypt JWE');
    }

    /**
     * MARK: decryptJWE
     */
    private function decryptJWE(string $idToken): ?string
    {
        $algorithmManager = new AlgorithmManager([
            new A256GCM,
            new A256CBCHS512,
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
     * MARK: mapUserToObject
     * Map the raw user array to a Socialite User instance.
     *
     * @param  array<string, mixed>  $user
     * @return User
     */
    protected function mapUserToObject(array $user)
    {
        assert(is_string($user['sub']));

        $name = '';
        $email = '';

        $raw = $user;

        // singpass login
        if (isset($user['sub_type'])) {
        } elseif (isset($user['sub_attributes']) && is_array($user['sub_attributes'])) {
            if (is_string($user['sub_attributes']['name'])) {
                $name = $user['sub_attributes']['name'];
            }

            if (is_string($user['sub_attributes']['email'])) {
                $email = $user['sub_attributes']['email'];
            }

            $raw = $user['sub_attributes'];
        }

        // myinfo
        elseif (isset($user['person_info']) && is_array($user['person_info'])) {
            // if (array_key_exists('name', $user) && is_array($user['name'])) {
            if (is_array($user['person_info']['name'])) {
                $name = $user['person_info']['name']['value'];
            }

            if (is_array($user['person_info']['email'])) {
                $email = $user['person_info']['email']['value'];
            }

            $user['person_info']['id'] = $user['sub'];

            $raw = $user['person_info'];
        }

        return (new User)->setRaw($raw)->map([
            'id' => $user['sub'],
            'name' => $name,
            'email' => $email,
        ]);
    }

    /**
     * MARK: getOpenIDConfiguration
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

        $response = Http::withHeader('Accept', 'application/json')->get(config('singpass-myinfo.openid_discovery_endpoint'));
        $openIDConfig = json_decode($response->body(), true);

        Cache::put('singpassOpenIDConfig', $openIDConfig, now()->addHour());

        /** @var array<string, mixed> */
        return $openIDConfig;
    }

    /**
     * MARK: verifyTokenSignature
     */
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
     * MARK: retrieveSingpassVerificationKey
     * Load the Singpass API verification key from Singpass JWKS endpoints
     *
     * @throws GuzzleException
     */
    private function retrieveSingpassVerificationKey(): JWK
    {
        try {
            $config = $this->getOpenIDConfiguration();

            assert(is_string($config['jwks_uri']));

            $response = Http::withHeader('Accept', 'application/json')->get($config['jwks_uri']);

            $singpassJWKS = $response->body();

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
     * MARK: getMyInfoJWE
     * Retrieve MyInfo JWE from Singpass
     */
    private function getMyInfoJWE(string $token): string
    {
        $config = $this->getOpenIDConfiguration();

        assert(is_string($config['userinfo_endpoint']));

        $dpopProof = $this->generateDPoPProof($config['userinfo_endpoint'], 'GET', $token);

        $response = Http::withHeaders([
            'Authorization' => "DPoP {$token}",
            'DPoP' => $dpopProof,
            'Accept' => 'application/json',
        ])
            ->get($config['userinfo_endpoint']);

        $content = $response->body();

        if ($response->failed()) {
            $errorResponse = json_decode($content, true);

            assert(is_array($errorResponse));
            assert(is_string($errorResponse['error']));

            throw new JweInvalidException($this->getErrorDescription($errorResponse['error']), $response->status());
        }

        return (string) $content;
    }

    /**
     * MARK: getSigningJwks
     *
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
     * MARK: getDecryptionJwks
     *
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
     * MARK: generateJwksForSingpassPortal
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
     * MARK: getPrivateKeyFileContent
     *
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

    /**
     * Base64URL encoding (no padding)
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $data, true)), '+/', '-_'), '=');
    }

    public function validateDpopProof(string $dpopProof, string $expectedMethod, string $expectedUrl, ?string $accessToken = null): array
    {
        $serializer = new CompactSerializer;
        $jws = $serializer->unserialize($dpopProof);

        // Get headers and payload
        $headers = $jws->getSignature(0)->getProtectedHeader();
        $payload = json_decode($jws->getPayload(), true);

        $errors = [];
        $checks = [];

        // Check 1: Header type
        if (($headers['typ'] ?? '') !== 'dpop+jwt') {
            $errors[] = "Header 'typ' must be 'dpop+jwt', got: ".($headers['typ'] ?? 'missing');
        } else {
            $checks[] = '✓ Header type is dpop+jwt';
        }

        // Check 2: Algorithm
        if (($headers['alg'] ?? '') !== 'ES256') {
            $errors[] = 'Algorithm must be ES256, got: '.($headers['alg'] ?? 'missing');
        } else {
            $checks[] = '✓ Algorithm is ES256';
        }

        // Check 3: JWK presence and format
        if (! isset($headers['jwk'])) {
            $errors[] = "Missing 'jwk' in header";
        } else {
            $jwk = $headers['jwk'];
            if (($jwk['kty'] ?? '') !== 'EC') {
                $errors[] = 'JWK kty must be EC';
            } elseif (($jwk['crv'] ?? '') !== 'P-256') {
                $errors[] = 'JWK crv must be P-256';
            } elseif (! isset($jwk['x']) || ! isset($jwk['y'])) {
                $errors[] = 'JWK missing x or y coordinates';
            } else {
                $checks[] = '✓ JWK is valid EC P-256 key';
            }

            // Ensure private key is NOT in header
            if (isset($jwk['d'])) {
                $errors[] = "CRITICAL: Private key 'd' found in header! Remove it!";
            }
        }

        // Check 4: Required claims
        $required = ['htm', 'htu', 'iat', 'exp', 'jti'];
        foreach ($required as $claim) {
            if (! isset($payload[$claim])) {
                $errors[] = "Missing required claim: $claim";
            }
        }
        if (empty(array_diff($required, array_keys($payload)))) {
            $checks[] = '✓ All required claims present';
        }

        // Check 5: HTTP method matches
        if (($payload['htm'] ?? '') !== strtoupper($expectedMethod)) {
            $errors[] = "htm claim '{$payload['htm']}' doesn't match expected '$expectedMethod'";
        } else {
            $checks[] = '✓ htm matches expected method';
        }

        // Check 6: URL normalization (no query params)
        $normalizedExpected = explode('?', $expectedUrl)[0];
        if (($payload['htu'] ?? '') !== $normalizedExpected) {
            $errors[] = "htu claim '{$payload['htu']}' doesn't match expected '$normalizedExpected' (must be normalized, no query params)";
        } else {
            $checks[] = '✓ htu is normalized correctly';
        }

        // Check 7: Timing (max 2 minutes)
        $iat = $payload['iat'] ?? 0;
        $exp = $payload['exp'] ?? 0;
        $duration = $exp - $iat;

        if ($duration > 120) {
            $errors[] = "Token lifetime ($duration seconds) exceeds 120 seconds maximum";
        } elseif ($duration <= 0) {
            $errors[] = 'Invalid token timing (exp <= iat)';
        } else {
            $checks[] = "✓ Token lifetime is $duration seconds (<= 120)";
        }

        // Check 8: ATH claim for userinfo
        if ($accessToken) {
            if (! isset($payload['ath'])) {
                $errors[] = "Missing 'ath' claim (required when access token is present)";
            } else {
                $expectedAth = rtrim(strtr(base64_encode(hash('sha256', $accessToken, true)), '+/', '-_'), '=');
                if ($payload['ath'] !== $expectedAth) {
                    $errors[] = "ath claim mismatch. Expected: $expectedAth, Got: {$payload['ath']}";
                } else {
                    $checks[] = '✓ ath claim matches SHA-256 hash of access token';
                }
            }
        } else {
            if (isset($payload['ath'])) {
                $errors[] = 'ath claim should not be present for token endpoint';
            } else {
                $checks[] = '✓ No ath claim (correct for token endpoint)';
            }
        }

        // Check 9: Verify signature
        try {
            $algorithmManager = new \Jose\Component\Core\AlgorithmManager([new ES256]);
            $verifier = new JWSVerifier($algorithmManager);
            $jwk = JWK::createFromJson(json_encode($headers['jwk']));

            if (! $verifier->verifyWithKey($jws, $jwk, 0)) {
                $errors[] = 'Signature verification failed';
            } else {
                $checks[] = '✓ Signature is valid';
            }
        } catch (\Exception $e) {
            $errors[] = 'Signature verification error: '.$e->getMessage();
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'checks' => $checks,
            'header' => $headers,
            'payload' => $payload,
            'raw_payload' => $jws->getPayload(),
        ];
    }
}
