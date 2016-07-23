<?php
/*
 * This file is part of Account.
 *
 * (c) 2014 Nord Software
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace phpnode\yii\password;

use phpnode\yii\password\strategies\PasswordStrategy;
use Yii;
use yii\base\Behavior;
use yii\base\ModelEvent;
use yii\db\ActiveRecord;

/**
 * @property ActiveRecord $owner
 */
class PasswordBehavior extends Behavior
{
    /**
     * The name of the attribute that contains the password salt
     * @var string
     */
    public $saltAttribute = "salt";

    /**
     * The name of the username attribute
     * @var string
     */
    public $usernameAttribute = "username";

    /**
     * The name of the attribute that contains the encoded password
     * @var string
     */
    public $passwordAttribute = "password";

    /**
     * The name of the attribute that contains the password strategy name
     * @var string
     */
    public $strategyAttribute = "passwordStrategy";

    /**
     * The name of the attribute that determines whether a user requires a new password or not
     * @var string
     */
    public $requireNewPasswordAttribute = "requiresNewPassword";

    /**
     * The name of the default password strategy
     * @var string
     */
    public $defaultStrategy = 'bcrypt';

    /**
     * Whether to automatically upgrade users on password strategies other than the default.
     * If this is true, user passwords will be re-encoded with the new strategy when they
     * successfully authenticate with an old strategy.
     * @var boolean
     */
    public $autoUpgrade = true;

    /**
     * An array of supported password strategies.
     * <pre>
     * [
     *   'hash' => [
     *     'class' => 'phpnode\yii\password\strategies\HashStrategy',
     *     'hashMethod' => ['sha1'],
     *     'workFactor' => 50
     *   ],
     *   'md5' => [
     *     'class' => 'phpnode\yii\password\strategies\LegacyMd5Strategy'
     *   ],
     * ]
     * </pre>
     * @var array
     */
    protected $_strategies = [];

    /**
     * Holds the hashed password, used to determine whether the user has changed their password
     * @var string
     */
    private $_hashedPassword;
    
    public $domainValueYes = true;

    /**
     * @inheritdoc
     */
    public function events()
    {
        return [
            ActiveRecord::EVENT_AFTER_FIND => 'afterFind',
            ActiveRecord::EVENT_BEFORE_INSERT => 'beforeSave',
            ActiveRecord::EVENT_BEFORE_UPDATE => 'beforeSave',
            ActiveRecord::EVENT_BEFORE_VALIDATE => 'beforeValidate',
        ];
    }

    /**
     * Compares the given password to the stored password for this model
     * @param string $password the plain text password to check
     * @return boolean true if the password matches, otherwise false
     */
    public function validatePassword($password)
    {
        $strategy = $this->getStrategy();
        if ($strategy === null) {
            return false; // no strategy
        }
        if ($this->saltAttribute) {
            $strategy->setSalt($this->owner->{$this->saltAttribute});
        }
        if ($this->usernameAttribute) {
            $strategy->setUsername($this->owner->{$this->usernameAttribute});
        }
        if (!$strategy->compare($password, $this->owner->{$this->passwordAttribute})) {
            return false;
        }
        if ($this->autoUpgrade && $strategy->name != $this->defaultStrategy) {
            if (!$this->changePassword($password, !$strategy->canUpgradeTo($this->getDefaultStrategy()))) {
                // couldn't upgrade their password, so ask them for a new password
                $this->owner->updateAttributes([
                    $this->requireNewPasswordAttribute => $this->domainValueYes
                ]);
            }
        }
        return true;
    }

    /**
     * Changes the user's password and saves the record
     * @param string $newPassword the plain text password to change to
     * @param boolean $runValidation whether to run validation or not.
     * If validate false, return false, and {UserModel} hasError(password).
     * @return boolean true if the password was changed successfully
     */
    public function changePassword($newPassword, $runValidation = true, $updateAttributes = true)
    {
        if ($runValidation) {
            $this->owner->{$this->passwordAttribute} = $newPassword;
            if ($this->owner->validate($this->passwordAttribute) === false) {
                return false;
            }
        }

        $this->changePasswordInternal($newPassword);

        if ($updateAttributes) {
            // updateAttributes instead of save to avoid trigger afterSave / beforeSave
            return $this->owner->updateAttributes(array(
                    $this->passwordAttribute,
                    $this->saltAttribute,
                    $this->strategyAttribute,
            ));
        }

    }

    /**
     * Generates a password reset code to use for this user.
     * This code can only be used once.
     * @return string the password reset code
     */
    public function getPasswordResetCode()
    {
        $salt = $this->saltAttribute ? $this->owner->{$this->saltAttribute} : '0';
        $password = $this->owner->{$this->passwordAttribute};
        return sha1(implode('|', [__CLASS__, __METHOD__, $this->owner->getPrimaryKey(), $salt, $password]));
    }

    /**
     * Changes the user's password but doesn't perform any saving
     * @param string $password the password to change to
     */
    protected function changePasswordInternal($password)
    {
        if ($this->autoUpgrade) {
            $strategy = $this->getDefaultStrategy();
        } else {
            $strategy = $this->getStrategy();
        }
        $salt = $strategy->getSalt(true);
        if ($this->saltAttribute && $salt !== false) {
            $this->owner->{$this->saltAttribute} = $salt;
        }
        $this->owner->{$this->strategyAttribute} = $strategy->name;
        $this->_hashedPassword = $this->owner->{$this->passwordAttribute} = $strategy->encode($password);
    }

    /**
     * Invoked after the model is found, stores the hashed user password
     * @param ModelEvent $event the raised event
     */
    public function afterFind($event)
    {
        $this->_hashedPassword = $event->sender->{$this->passwordAttribute};
    }

    /**
     * Invoked before the model is saved, re-hashes the password if required
     * @param ModelEvent $event the raised event
     */
    public function beforeSave($event)
    {
        $password = $event->sender->{$this->passwordAttribute};
        if ($password !== $this->_hashedPassword && $password !== '') {
            $this->changePasswordInternal($password);
        } else if ($password === '' && $this->_hashedPassword !== '') {
            $event->sender->{$this->passwordAttribute} = $this->_hashedPassword;
        }
    }

    /**
     * Invoked before the model is validated.
     * Validates the password first
     * @param ModelEvent $event the raised event
     */
    public function beforeValidate($event)
    {
        $strategy = $this->getStrategy();
        $password = $event->sender->{$this->passwordAttribute};
        if ($strategy !== null && $password !== $this->_hashedPassword && $password !== '') {
            $strategy->attributes = [$this->passwordAttribute];
            $strategy->validateAttributes($event->sender);
        }
    }

    /**
     * Sets the strategies to use
     * @param PasswordStrategy[]|array $strategies the strategies to add
     */
    public function setStrategies($strategies)
    {
        foreach ($strategies as $name => $strategy) {
            if (!($strategy instanceof PasswordStrategy)) {
                $strategy = Yii::createObject($strategy);
            }
            $strategy->name = $name;
            $strategies[$name] = $strategy;
        }
        $this->_strategies = $strategies;
    }

    /**
     * Gets the password strategies
     * @return array the password strategies
     */
    public function getStrategies()
    {
        return $this->_strategies;
    }

    /**
     * Gets the default password strategy
     * @return PasswordStrategy the default password strategy
     */
    public function getDefaultStrategy()
    {
        return isset($this->_strategies[$this->defaultStrategy]) ? $this->_strategies[$this->defaultStrategy] : null;
    }

    /**
     * Gets the password strategy to use for this model
     * @return PasswordStrategy the password strategy
     */
    public function getStrategy()
    {
        $strategy = $this->owner->{$this->strategyAttribute};
        return isset($this->_strategies[$strategy]) ? $this->_strategies[$strategy] : $this->getDefaultStrategy();
    }
}
