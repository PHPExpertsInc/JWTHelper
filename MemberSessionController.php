<?php declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Managers\LegacySessionManager;
use App\Models\Users\Member;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Tymon\JWTAuth\JWTGuard;

class MemberSessionController extends BaseAuthController
{
    /** @var LegacySessionManager */
    private $legacySession;

    public function __construct()
    {
        /** @var JWTGuard $memberGuard */
        $memberGuard = auth('members');
        $this->authGuard = $memberGuard;
    }

    public function store(Request $request)
    {
        // Attempt via MD5 first.
        $oldGuard = new LegacySessionManager($this->authGuard);
        try {
            $token = $oldGuard->loginMD5($request->input('username'), $request->input('password'));
        } catch (\Exception $e) {
            // Do nothing. It will then attempt a regular login.
        }

        if (!empty($token)) {
            return $this->respondWithToken($token);
        }

        $credentials = request(['username', 'password']);

        $member = Member::locate($credentials['username']);
        if (!$member || !$token = $this->authGuard->attempt($credentials)) {
            return new JsonResponse(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function destroy()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
}
