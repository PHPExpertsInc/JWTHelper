<?php declare(strict_types=1);

namespace Tests\Feature\Members;

use App\Mail\PasswordResetEmail;
use Illuminate\Foundation\Testing\TestResponse;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Testing\Fakes\MailFake;
use PHPUnit\Framework\ExpectationFailedException;

class ResetPasswordTest extends TestCase
{
    public const MEMBER_ID = 14043903;
    public const ZUORA_ID = '8a80c3326cab012b016dbb7413695ea1';
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

    public function testCanRequestAPasswordResetToken()
    {
        //(new MailFake())
        Mail::fake();

        $checkTheAPIRoute = function () {
            // Use the native `json()` method, because `patch()` will include the X-API-Key,
            // which would invalidate this test.
            $response = $this->json('POST', "/auth/members/tokens", [
                'email' => self::EMAIL,
            ]);
            self::assertEquals(JsonResponse::HTTP_ACCEPTED, $response->getStatusCode());
            self::assertEquals(['message' => 'Reset token sent.'], $response->decodeResponseJson());
        };

        $checkTheResetEmail = function () {
            $resetToken = '';
            Mail::assertSent(PasswordResetEmail::class, function (PasswordResetEmail $mail) use (&$resetToken) {
                // Exfiltrate the email token.
                $mail->build();
                $resetToken = substr(
                    $mail->resetURL,
                    strrpos($mail->resetURL, '/') + 1
                );

                return $mail->hasTo(self::EMAIL) &&
                    $mail->subject === 'Reset your USLS member password';
            });

            return $resetToken;
        };

        $checkTheAPIRoute();
        $resetToken = $checkTheResetEmail();

        return $resetToken;
    }

    /** @depends testCanRequestAPasswordResetToken */
    public function testCanVerifyThatAResetTokenIsValid(string $resetToken)
    {
        $response = $this->json('GET', "/auth/members/tokens/$resetToken");
        $response->assertStatus(JsonResponse::HTTP_OK);

        self::assertEquals($resetToken, $response->decodeResponseJson('reset_token'));
    }

    /** @depends testCanRequestAPasswordResetToken */
    public function testCanResetAMembersPasswordWithAResetToken(string $resetToken)
    {
        $newPassword = '222222';

        $zuoraId = self::ZUORA_ID;
        $response = $this->json('PUT', "/auth/members/$zuoraId/password", [
            'reset_token'           => $resetToken,
            'password'              => $newPassword,
            'password_confirmation' => $newPassword,
        ]);
        $response->assertStatus(JsonResponse::HTTP_OK);

        $decoded = $response->decodeResponseJson();

        self::assertArrayHasKey('access_token', $decoded);
        self::assertNotEmpty($decoded['access_token']);

        try {
            $this->login(self::USERNAME, self::PASSWORD);
            self::fail('Still logged in with the old password.');
        } catch (ExpectationFailedException $e) {
            self::assertTrue(true);
        }

        $this->login(self::USERNAME, $newPassword);
    }

    /** @depends testCanRequestAPasswordResetToken */
    public function testThePasswordConfirmationMustMatch(string $resetToken)
    {
        $jwtToken = $this->token;

        $zuoraId = self::ZUORA_ID;
        // Use the native `json()` method, because `patch()` will include the X-API-Key,
        // which would invalidate this test.
        $response = $this->json('PUT', "/auth/members/$zuoraId/password", [
            'reset_token'           => $resetToken,
            'password'              => '2222222',
            'password_confirmation' => '3333333',
        ]);
        $response->assertStatus(JsonResponse::HTTP_BAD_REQUEST);
        $decoded = $response->decodeResponseJson();

        self::assertFalse($decoded['success']);
        self::assertEquals('The given data was invalid.', $decoded['message']);
        self::assertNotEmpty($decoded['errors']);
        self::assertNotEmpty($decoded['errors']['password']);
        self::assertEquals('The password confirmation does not match.', $decoded['errors']['password'][0]);
    }
}










