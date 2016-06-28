<?php

namespace HWI\Bundle\OAuthBundle\OAuth\Response;

/**
 * Class parsing the properties by given path options.
 *
 * @author Tymon Terlikiewicz <tymon+github@batmaid.com>
 */
class AzureB2CUserResponse extends PathUserResponse
{
    public function getStreet()
    {
        return $this->getValueForPath('street');
    }

    public function getZip()
    {
        return $this->getValueForPath('postalCode');
    }

    public function getCountry()
    {
        return $this->getValueForPath('country');
    }

    public function getCity()
    {
        return $this->getValueForPath('city');
    }

    public function getMobile()
    {
        return $this->getValueForPath('mobile');
    }
}
