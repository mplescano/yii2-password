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

use Yii;
use yii\base\Model;
use yii\validators\Validator;

abstract class PasswordStrategy extends Validator
{
    // Error messages
    const MESSAGE_TOO_SHORT = 'tooShort';
    const MESSAGE_TOO_LONG = 'tooLong';
    const MESSAGE_DIGITS = 'digits';
    const MESSAGE_LOWERCASE_LETTERS = 'lowercaseLetters';
    const MESSAGE_UPPERCASE_LETTERS = 'uppercaseLetters';
    const MESSAGE_SPECIAL_CHARACTERS = 'specialCharacters';

    /**
     * The name of this password strategy
     * @var string
     */
    public $name;

    /**
     * The number of days a password is valid for before it should be changed.
     * Defaults to false, meaning passwords do not expire
     * @var integer|boolean
     */
    public $daysValid = false;

    /**
     * The minimum password length
     * @var integer
     */
    public $minLength = 6;

    /**
     * The maximum password length.
     * There is no good reason to set this value unless you're using it for legacy authentication
     * Defaults to false meaning no maximum password length.
     * @var integer|boolean
     */
    public $maxLength = false;

    /**
     * The minimum number of upper case letters that should appear in passwords.
     * Defaults to 0 meaning no minimum.
     * @var integer
     */
    public $minUpperCaseLetters = 0;

    /**
     * The minimum number of lower case letters that should appear in passwords.
     * Defaults to 0 meaning no minimum.
     * @var integer
     */
    public $minLowerCaseLetters = 0;

    /**
     * The minimum number of digits that should appear in passwords.
     * Defaults to 0 meaning no minimum.
     * @var integer
     */
    public $minDigits = 0;

    /**
     * The minimum number of special characters that should appear in passwords.
     * Defaults to 0 meaning no minimum.
     * @var integer
     */
    public $minSpecialCharacters = 0;

    /**
     * The special characters that should appear in passwords if $minSpecialCharacters is set
     * @var array
     */
    public $specialCharacters = [" ", "'", "~", "!", "@", "#", "£", "$", "%", "^", "&", "\*", "(", ")", "_", "-", "\+", "=", "[", "]", "\\", "\|", "{", "}", ";", ":", '"', "\.", ",", "\/", "<", ">", "\?", "`"];

    /**
     * The validation error messages to use
     * @var array
     */
    public $messages = [];

    /**
     * Message source to use for this extension.
     * @var string
     */
    public $messageSource = 'yii\i18n\PhpMessageSource';

    /**
     * @var string the salt to use for this password, if supported by this strategy
     */
    private $_salt;

    /**
     * @var string the username for this password
     */
    private $_username;

    /**
     * Encode a plain text password.
     * Child classes should implement this method and do their encoding here
     * @param string $password the plain text password to encode
     * @return string the encoded password
     */
    abstract public function encode($password);

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        $this->registerTranslations();

        $this->messages = array_merge(
            [
                self::MESSAGE_TOO_SHORT => PasswordStrategy::t(
                    'errors',
                    "{attribute} is too short, minimum is {n} {n, plural, =1{character} other{characters}}.",
                    ['n' => $this->minLength]
                ),
                self::MESSAGE_TOO_LONG => PasswordStrategy::t(
                    'errors',
                    "{attribute} is too long, maximum is {n} {n, plural, =1{character} other{characters}}.",
                    ['n' => $this->maxLength]
                ),
                self::MESSAGE_DIGITS => PasswordStrategy::t(
                    'errors',
                    "{attribute} should contain at least {n} {n, plural, =1{digit} other{digits}}.",
                    ['n' => $this->minDigits]
                ),
                self::MESSAGE_UPPERCASE_LETTERS => PasswordStrategy::t(
                    'errors',
                    "{attribute} should contain at least {n} upper case {n, plural, =1{character} other{characters}}.",
                    ['n' => $this->minUpperCaseLetters]
                ),
                self::MESSAGE_LOWERCASE_LETTERS => PasswordStrategy::t(
                    'errors',
                    "{attribute} should contain at least {n} lower case {n, plural, =1{character} other{characters}}.",
                    ['n' => $this->minLowerCaseLetters]
                ),
                self::MESSAGE_SPECIAL_CHARACTERS => PasswordStrategy::t(
                    'errors',
                    "{attribute} should contain at least {n} non alpha numeric {n, plural, =1{character} other{characters}}.",
                    ['n' => $this->minSpecialCharacters]
                ),
            ],
            $this->messages
        );
    }

    /**
     * TODO Write this
     */
    public function registerTranslations()
    {
        Yii::$app->i18n->translations['phpnode/password/*'] = [
            'class' => $this->messageSource,
            'sourceLanguage' => 'en-US',
            'basePath' => '@phpnode/yii/password/messages',
        ];
    }

    /**
     * Generates a random salt.
     * @return string|boolean the generated salt, or false if not supported by this strategy
     */
    protected function generateSalt()
    {
        return false;
    }

    /**
     * @inheritdoc
     */
    public function validateAttribute($object, $attribute)
    {
        $password = $object->{$attribute};
        $length = mb_strlen($password);
        if ($this->minLength && $length < $this->minLength) {
            $this->addError($object, $attribute, $this->messages[self::MESSAGE_TOO_SHORT]);
            return false;
        }
        if ($this->maxLength && $length > $this->maxLength) {
            $this->addError($object, $attribute, $this->messages[self::MESSAGE_TOO_LONG]);
            return false;
        }
        if ($this->minDigits) {
            $digits = "";
            if (preg_match_all("/[\d+]/u", $password, $matches)) {
                $digits = implode("", $matches[0]);
            }
            if (mb_strlen($digits) < $this->minDigits) {
                $this->addError($object, $attribute, $this->messages[self::MESSAGE_DIGITS]);
                return false;
            }
        }
        if ($this->minUpperCaseLetters) {
            $upper = "";
            if (preg_match_all("/[A-Z]/u", $password, $matches)) {
                $upper = implode("", $matches[0]);
            }
            if (mb_strlen($upper) < $this->minUpperCaseLetters) {
                $this->addError($object, $attribute, $this->messages[self::MESSAGE_UPPERCASE_LETTERS]);
                return false;
            }
        }
        if ($this->minLowerCaseLetters) {
            $lower = "";
            if (preg_match_all("/[a-z]/u", $password, $matches)) {
                $lower = implode("", $matches[0]);
            }
            if (mb_strlen($lower) < $this->minLowerCaseLetters) {
                $this->addError($object, $attribute, $this->messages[self::MESSAGE_LOWERCASE_LETTERS]);
                return false;
            }
        }
        if ($this->minSpecialCharacters) {
            $special = "";
            if (preg_match_all("/[" . implode("|", $this->specialCharacters) . "]/u", $password, $matches)) {
                $special = implode("", $matches[0]);
            }
            if (mb_strlen($special) < $this->minSpecialCharacters) {
                $this->addError($object, $attribute, $this->messages[self::MESSAGE_SPECIAL_CHARACTERS]);
                return false;
            }
        }
        return true;
    }

    /**
     * Compare a plain text password to the given encoded password
     * @param string $password the plain text password to compare
     * @param string $encoded the encoded password to compare to
     * @return boolean true if the passwords are equal, otherwise false
     */
    public function compare($password, $encoded)
    {
        return $this->encode($password) === $encoded;
    }

    /**
     * Checks whether this strategy can be upgraded to another given strategy.
     * If this strategy's complexity requirements are equal or greater than that
     * of the given strategy, then it can be upgraded. Otherwise the user must be
     * prompted to enter a new password that meets the complexity requirements.
     * @param PasswordStrategy $strategy the strategy to upgrade to
     * @return boolean true if this strategy can be upgraded to the given strategy
     */
    public function canUpgradeTo(PasswordStrategy $strategy)
    {
        if ($strategy->minLength && $strategy->minLength > $this->minLength) {
            return false;
        }
        if ($strategy->minDigits > $this->minDigits) {
            return false;
        }
        if ($strategy->minLowerCaseLetters > $this->minLowerCaseLetters) {
            return false;
        }
        if ($strategy->minUpperCaseLetters > $this->minUpperCaseLetters) {
            return false;
        }
        if ($strategy->minSpecialCharacters > $this->minSpecialCharacters) {
            return false;
        }
        return true;
    }

    /**
     * Sets the salt to use with this strategy, if supported
     * @param string $salt the salt
     */
    public function setSalt($salt)
    {
        $this->_salt = $salt;
    }

    /**
     * Gets the salt to use with this strategy, if supported.
     * @param boolean $forceRefresh whether to force generate a new salt
     * @return string the generated salt
     */
    public function getSalt($forceRefresh = false)
    {
        if ($this->_salt === null || $forceRefresh) {
            $this->_salt = $this->generateSalt();
        }
        return $this->_salt;
    }

    /**
     * Sets the username to use with this strategy
     * @param  string $username the username
     */
    public function setUsername($username)
    {
        $this->_username = $username;
    }

    /**
     * Gets the username to use with this strategy
     * @return string the username
     */
    public function getUsername()
    {
        return $this->_username;
    }

    /**
     * Translates the the given text.
     *
     * @param string $category message category.
     * @param string $message text to translate.
     * @param array $params additional parameters.
     * @return string translated text.
     */
    public static function t($category, $message, $params = [], $language = null)
    {
        return Yii::t('phpnode/password/' . $category, $message, $params, $language);
    }
}
