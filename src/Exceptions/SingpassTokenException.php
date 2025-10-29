<?php

namespace Shokanshi\SingpassMyInfo\Exceptions;

use Exception;
use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SingpassTokenException extends HttpException
{
    /**
     * @param  int  $statusCode  The HTTP status code for the response.
     * @param  string  $message  The exception message.
     * @param  Exception|null  $previous  The previous exception used for exception chaining.
     * @param  array<string, string>  $headers  A list of HTTP headers to send with the response.
     * @param  int  $code  The internal exception code.
     */
    public function __construct(int $statusCode = 500, string $message = 'GET request to Singpass Token endpoint failed', ?Exception $previous = null, array $headers = [], int $code = 0)
    {
        parent::__construct($statusCode, $message, $previous, $headers, $code);
    }

    /**
     * Render the exception into an HTTP response.
     */
    public function render(): JsonResponse
    {
        return response()->json([
            'message' => $this->message,
        ], $this->getStatusCode());
    }
}
