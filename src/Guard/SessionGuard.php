<?php

namespace Lab404\Impersonate\Guard;

use Illuminate\Auth\SessionGuard as BaseSessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;

class SessionGuard extends BaseSessionGuard
{
    /**
     * Log a user into the application without firing the Login event.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function quietLogin(Authenticatable $user)
    {
        $this->updateSession($user->getAuthIdentifier());

        $this->setUser($user);
    }

    /**
     * Logout the user without updating remember_token
     * and without firing the Logout event.
     *
     * @param   void
     * @return  void
     */
    public function quietLogout()
    {
        $this->clearUserDataFromStorage();

        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Get a unique identifier for the auth session value.
     *
     * @return string
     */
    public function getName()
    {
        $hash = config('auth.use-base-session-guard-hash', false)
            ? sha1(parent::class)
            : sha1(static::class);
        return 'login_'.$this->name.'_'.$hash;
    }
}
