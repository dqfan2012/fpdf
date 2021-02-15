<?php

/*
* FPDFProtection Helper                                                        *
*                                                                              *
* Version: 1.0.5                                                               *
* Date:    2019-02-15                                                          *
* Author:  Olivier PLATHEY                                                     *
* Updated: Samuel Stidham                                                      *
* Updated Date: 2020-02-15                                                     *
* Updated For: PSR-4 and Composer                                              *
*/

namespace FPDF;

class Helper
{
    public static function RC4($key, $data)
    {
        if (function_exists('openssl_encrypt')) {
            return openssl_encrypt($data, 'RC4-40', $key, OPENSSL_RAW_DATA);
        } elseif (function_exists('mcrypt_encrypt')) {
            return @mcrypt_encrypt(MCRYPT_ARCFOUR, $key, $data, MCRYPT_MODE_STREAM, '');
        } else {
            static $last_key, $last_state;

            if($key != $last_key)
            {
                $k = str_repeat($key, 256/strlen($key)+1);
                $state = range(0, 255);
                $j = 0;
                for ($i=0; $i<256; $i++){
                    $t = $state[$i];
                    $j = ($j + $t + ord($k[$i])) % 256;
                    $state[$i] = $state[$j];
                    $state[$j] = $t;
                }
                $last_key = $key;
                $last_state = $state;
            }
            else
                $state = $last_state;

            $len = strlen($data);
            $a = 0;
            $b = 0;
            $out = '';
            for ($i=0; $i<$len; $i++){
                $a = ($a+1) % 256;
                $t = $state[$a];
                $b = ($b+$t) % 256;
                $state[$a] = $state[$b];
                $state[$b] = $t;
                $k = $state[($state[$a]+$state[$b]) % 256];
                $out .= chr(ord($data[$i]) ^ $k);
            }

            return $out;
        }
    }
}