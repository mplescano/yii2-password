<?php
/*
 * This file is part of Account.
 *
 * (c) 2014 Charles Pick
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace phpnode\yii\password\strategies;

class HashStrategy extends PasswordStrategy
{
    /**
     * The work factor used when hashing passwords.
     * The higher the work factor the more computationally expensive
     * it is to encode and validate passwords. So it makes your passwords
     * harder to crack, but it can also be a burden on your own server.
     *
     * @var integer
     */
    public $workFactor = 100;

    /**
     * The hash method to use when encoding passwords
     * @var Callable
     */
    public $hashMethod = "sha1";

    /**
     * Generates a random salt to use when noncing passwords
     * @return string the random salt
     */
    protected function generateSalt()
    {
        return call_user_func_array($this->hashMethod, array(uniqid("", true)));
    }

    /**
     * @inheritdoc
     */
    public function encode($password)
    {
        $hash = $this->getSalt() . "###" . $password;
        for ($i = 0; $i < $this->workFactor; $i++) {
            $hash = call_user_func_array($this->hashMethod, array($hash));
        }
        return $hash;
    }
}
