<?php
/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */

namespace FastD\BasicAuthenticate;

/**
 * Interface AuthenticatorInterface
 * @package FastD\BasicAuthenticate
 */
interface AuthenticatorInterface
{
    /**
     * @return mixed
     */
    public function getUserInfo();

    /**
     * @param $user
     * @param $password
     * @return mixed
     */
    public function validate($user, $password);
}
