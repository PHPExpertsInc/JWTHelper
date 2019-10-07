<?php declare(strict_types=1);

/**
 * This file is part of JWTHelper, a PHP Experts, Inc., Project.
 *
 * Copyright © 2019 PHP Experts, Inc.
 * Author: Theodore R. Smith <theodore@phpexperts.pro>
 *   GPG Fingerprint: 4BF8 2613 1C34 87AC D28F  2AD8 EB24 A91D D612 5690
 *   https://www.phpexperts.pro/
 *   https://github.com/PHPExpertsInc/JWTHelper
 *
 * This file is licensed under the MIT License.
 */

namespace PHPExperts\JWTHelper;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\JWT;

class JWTHelper
{
    /**
     * @throws JWTException
     */
    public static function authenticate()
    {
        try {
            /** @var JWT $jwt */
            $jwt = app('tymon.jwt')->parseTokeN();
            // See if the token is expired. It will throw a TokenExpiredException if so.
            $ttl = $jwt->parseToken()->getClaim('exp');

            if (!$jwt->check()) {
                throw new JWTException('Invalid username / password');
            }
        } catch (TokenExpiredException $e) {
            throw new JWTException('Expired JWT Token');
        } catch (TokenInvalidException $e) {
            throw new JWTException('Invalid JWT Token');
        } catch (JWTException $e) {
            throw new JWTException('Missing JWT Token');
        }
    }
}
