<?php declare(strict_types=1);

namespace App\Models\Users;

use App\Models\USLS\DTOs\Response\VerifiedRefreshTokenDTO;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use PHPExperts\ConciseUuid\ConciseUuid;
use PHPExperts\DataTypeValidator\InvalidDataTypeException;
use PHPExperts\JWTHelper\JWTHelper;
use Symfony\Component\Console\Exception\LogicException;

/**
 * @FIXME: Fix/add all of the table columns here.
 *
 * @property int    $id                    The member's ID.
 * @property string $algorithm             The password hashing algorithm used.
 * @property string $reset_token           A ConciseUUID password reset token.
 * @property Carbon $token_created_at      Tokens are expired after 2 hours.
 * @property string $auth_token            A ConciseUUID password for legacy auth.
 * @property Carbon $auth_token_created_at Tokens are expired after 2 hours.
 *
 * Relationships:
 * @property Member $member
 */
class MemberSecurity extends Model
{
    public const EXPIRE_TOKEN_HOURS = 2;

    protected $table = 'members_security';

    /**
     * The attributes that are NOT mass assignable.
     *
     * @var array
     */
    protected $guarded = ['password'];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    protected $dates = ['token_created_at'];

    public static function boot()
    {
        parent::boot();

        static::creating(function (self $model) {
            $rules = $model::creationValidationRules();

            $validator = app('validator')->make($model->toArray(), $rules);
            if ($validator->fails()) {
                throw new ValidationException($validator, $validator->errors());
            }
        });
    }

    public function member(): BelongsTo
    {
        return $this->belongsTo(Member::class, 'id');
    }

    /**
     * Validation rules for creation of employee in a company.
     *
     * @return array Set of validation rules
     */
    public static function creationValidationRules(): array
    {
        return [
        ];
    }

    /**
     * As of now there are no update validation rules for an order as it cannot be updated.
     *
     * @return array
     */
    public static function updateValidationRules(): array
    {
        return [];
    }

    /**
     * Attempts to log in via the legacy MD5 auth.
     *
     * @param  string      $username
     * @param  string      $password
     * @return Member|null
     */
    public static function attemptLegacyAuth(string $username, string $password): ?Member
    {
        // @FIXME: Implement a procedure to port users to bcrypt.
        /** @var Member|null $member */
        $member = Member::query()
            ->join('members_security', 'members_security.id', '=', 'members.id')
            ->where('algorithm', 'md5')
            ->where(function (EloquentBuilder $query) use ($username) {
                $query->where(['email'    => $username])
                    ->orWhere(['username' => $username]);
            })
            ->where('password', md5($password))
            ->first();

        return $member;
    }

    /**
     * Generates a password reset token.
     *
     * @param  int    $memberId
     * @return string
     */
    public static function generateResetToken(int $memberId): string
    {
        /** @var self $memberSecurity */
        $memberSecurity = self::query()->findOrFail($memberId);

        $memberSecurity->reset_token = ConciseUuid::generateNewId();
        $memberSecurity->token_created_at = Carbon::now();
        $memberSecurity->save();

        return $memberSecurity->reset_token;
    }

    /**
     * Check whether the token is valid or not.
     * @param  string      $token
     * @param  string|null $forEmail
     * @return
     */
    public static function ensureValidToken(?string $token, string $forEmail = null): VerifiedRefreshTokenDTO
    {
        try {
            /** @var MemberSecurity $memberSecurity */
            $memberSecurity = self::query()
                ->where(['reset_token' => $token])
                ->firstOrFail();
        } catch (ModelNotFoundException $e) {
            throw new InvalidArgumentException('For some strange reason, your security token has become corrupted and is no longer valid. Please try clearing your browser\'s cookies for this site, going into Incognito mode, or use another browser. If all else fails, please contact Customer Support.');
        }

        if ($memberSecurity->token_created_at->addHours(self::EXPIRE_TOKEN_HOURS) < Carbon::now()) {
            throw new InvalidDataTypeException('The security token you provided has expired. Please request a new a new one.');
        }

        try {
            /** @var Member $member */
            $member = Member::query()->findOrFail($memberSecurity->id);
        } catch (ModelNotFoundException $e) {
            throw new InvalidArgumentException('The security token provided by your browser was issued for somebody else\'s account. Please log in again.');
        }

        if ($forEmail && $member->email != $forEmail) {
            throw new LogicException("A reset token was used for the wrong email: $forEmail.");
        }

        return new VerifiedRefreshTokenDTO([
            'user_id'     => $member->zuora_id,
            'email'       => $member->email,
            'reset_token' => $token,
        ]);
    }

    public function changePassword(string $newPassword, string $action = 'changePassword'): string
    {
        $member = $this->member;

        // @todo This can be simplified to one update once members_security is a concrete table.
        DB::transaction(function () use ($member, $newPassword) {
            // @security ONLY pass these 4 parameters to the model.
            //           Passing more would allow an OUTSIDER to change ANY user's details
            //           with merely a valid resetToken...
            $member->legacy_member_shadow->update([
                'shadow' => md5($newPassword),
            ]);

            // NOTE: Eloquent will throw an exception -and- rollback the transaction on error.
            //       So there's not really any point in doing -additional- status checks.
            $member->member_security->update([
                'reset_token'      => null,
                // @FIXME: This needs to be updated to the latest bcrypt.
                'algorithm'        => 'md5',
                'token_created_at' => null,
            ]);
        });

        $token = JWTHelper::login($member, [$action => true]);

        return $token;
    }

    public static function resetPassword(string $email, string $resetToken, string $newPassword): string
    {
        $verifiedDTO = MemberSecurity::ensureValidToken($resetToken, $email);
        if ($email !== $verifiedDTO->email) {
            throw new InvalidArgumentException(
                'The email used for resetting the password doesn\'t match the member\'s email'
            );
        }

        try {
            $mySecrets = MemberSecurity::query()
                ->whereHas('member', function (EloquentBuilder $query) use ($email, $verifiedDTO) {
                    $query->where([
                        'zuora_id'    => $verifiedDTO->user_id,
                        'email' => $email,
                    ]);
            })->firstOrFail();
        } catch (ModelNotFoundException $e) {
            throw new InvalidArgumentException('We were unable to find a matching account for this security token.');
        }

        $token = $mySecrets->changePassword($newPassword, 'resetPassword');

        return $token;
    }
}
