<?php declare(strict_types=1);

namespace Tests\Feature\Members;

use Illuminate\Foundation\Testing\TestResponse;
use Illuminate\Http\Response;
use Tests\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected $token = '';

    public function login(string $username, string $password): TestResponse
    {
        $response = $this->json('POST', '/auth/members/login', [
            'username' => $username,
            'password' => $password,
        ]);

        $decoded = $response->decodeResponseJson();
        self::assertEquals(Response::HTTP_OK, $response->getStatusCode(), json_encode($decoded));

        $this->token = $decoded['access_token'];

        return $response;
    }

    /**
     * @param $uri
     * @param array $headers
     *
     * @return TestResponse
     */
    public function get($uri, array $headers = [])
    {
        return parent::get($uri, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     * @param array  $payload
     * @param array  $headers
     *
     * @return TestResponse
     */
    public function post($uri, array $payload = [], array $headers = [])
    {
        return parent::json('POST', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     * @param array  $payload
     * @param array  $headers
     *
     * @return TestResponse
     */
    public function put($uri, array $payload = [], array $headers = [])
    {
        return parent::json('PUT', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     * @param array  $payload
     * @param array  $headers
     *
     * @return TestResponse
     */
    public function patch($uri, array $payload = [], array $headers = [])
    {
        return parent::json('PATCH', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }

    /**
     * @param string $uri
     * @param array  $payload
     * @param array  $headers
     *
     * @return TestResponse
     */
    public function delete($uri, array $payload = [], array $headers = [])
    {
        return parent::json('DELETE', $uri, $payload, $headers + [
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $this->token,
        ]);
    }
}
