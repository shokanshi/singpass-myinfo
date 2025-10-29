<?php

namespace Shokanshi\SingpassMyInfo\Exceptions;

use Exception;
use Illuminate\Http\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SingpassGetEndpointException extends HttpException
{
    /**
     * @param  int  $statusCode  The HTTP status code for the response.
     * @param  string  $message  The exception message.
     * @param  Exception|null  $previous  The previous exception used for exception chaining.
     * @param  array<string, string>  $headers  A list of HTTP headers to send with the response.
     * @param  int  $code  The internal exception code.
     */
    public function __construct(int $statusCode = 400, string $message = 'An error has occurred when processing your request.', ?Exception $previous = null, array $headers = [], int $code = 0)
    {
        parent::__construct($statusCode, $message, $previous, $headers, $code);
    }

    /**
     * Render the exception into an HTTP response.
     */
    public function render(): RedirectResponse
    {
        return redirect()->route('login')->withErrors(
            [
                'singpass' => [
                    [
                        'title' => 'Request Error',
                        'description' => $this->message,
                    ],
                ],
            ]
        );
    }
}
