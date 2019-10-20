<?php declare(strict_types=1);

namespace Tests\Feature\Members;

use Illuminate\Foundation\Testing\TestResponse;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\ExpectationFailedException;

class AuthenticationTest extends TestCase
{
    public const MEMBER_ID = 14043903;
    public const ZUORA_ID = '8a80c3326cab012b016dbb7413695ea1';
    public const ALT_ZUORA_ID = '8a80c3326cab012b016d72e465dd49a2';
    public const USERNAME = 'TX150002';
    public const EMAIL = 'auth_tests@nousls.com';
    public const PASSWORD = '123456';

    public function setUp(): void
    {
        parent::setUp();

        // Always manually reset the password back to 'e10adc3949ba59abbe56e057f20f883e' (123456).
        DB::table('members_security')
            ->where(['id' => self::MEMBER_ID])
            ->update(['password' => 'e10adc3949ba59abbe56e057f20f883e']);
    }

    public function testCanLogin()
    {
        // Hard-coded to the TX150002 user on QA, password 123456
        $response = $this->login(self::USERNAME, self::PASSWORD);
        $decoded = $response->decodeResponseJson();

        return $decoded['access_token'];
    }

    public function testCannotLogInWithBadCredentials()
    {
        $response = $this->post('/auth/members/login', [
            'username' => self::USERNAME,
            'password' => 'This is the wrong password!',
        ]);

        self::assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $decoded = $response->decodeResponseJson();
        self::assertNotEmpty($decoded['error']);
        self::assertEquals('Unauthorized', $decoded['error']);
    }

    public function testCanUpdatePasswords()
    {
        $this->login(self::USERNAME, self::PASSWORD);
        $jwtToken = $this->token;

        $zuoraId = self::ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $newPassword = self::PASSWORD . '1';
        $response = $this->json('PATCH', "/auth/members/$zuoraId/password", [
            'password'              => $newPassword,
            'password_confirmation' => $newPassword,
        ], [
            'Authorization'         => "Bearer $jwtToken",
        ])->decodeResponseJson();

        self::assertArrayHasKey('access_token', $response);
        self::assertNotEmpty($response['access_token']);

        try {
            $this->login(self::USERNAME, self::PASSWORD);
            self::fail('Still logged in with the old password.');
        } catch (ExpectationFailedException $e) {
            self::assertTrue(true);
        }

        $this->login(self::USERNAME, $newPassword);
    }

    /** @testdox Cannot update another user's password */
    public function testCannotUpdateAnotherUsersPassword()
    {
        $this->login(self::USERNAME, self::PASSWORD);
        $jwtToken = $this->token;

        $zuoraId = self::ALT_ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $newPassword = self::PASSWORD . '1';
        $response = $this->json('PATCH', "/auth/members/$zuoraId/password", [
            'password'              => $newPassword,
            'password_confirmation' => $newPassword,
        ], [
            'Authorization'         => "Bearer $jwtToken",
        ]);

        self::assertEquals(JsonResponse::HTTP_BAD_REQUEST, $response->getStatusCode());
        $message = json_decode($response->getContent(), true)['message'];
        self::assertContains('Your session has become corrupted (token/user mismatch).', $message);
    }

    public function testThePasswordConfirmationMustMatch()
    {
        $this->login(self::USERNAME, self::PASSWORD);
        $jwtToken = $this->token;

        $zuoraId = self::ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $response = $this->json('PATCH', "/auth/members/$zuoraId/password", [
            'password'              => self::PASSWORD,
            'password_confirmation' => self::PASSWORD . 'doesnt match',
        ], [
            'Authorization'         => "Bearer $jwtToken",
        ])->decodeResponseJson();

        self::assertFalse($response['success']);
        self::assertEquals('The given data was invalid.', $response['message']);
        self::assertNotEmpty($response['errors']);
        self::assertNotEmpty($response['errors']['password']);
        self::assertEquals('The password confirmation does not match.', $response['errors']['password'][0]);
    }
}
