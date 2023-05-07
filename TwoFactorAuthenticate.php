<?php

class TwoFactorAuthenticate
{
    const BITS_5_RIGHT = 31;
    protected static $CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    protected $length = 6;

    public static function b32_encode($data)
    {
        $dataSize = strlen($data);
        $res = '';
        $remainder = 0;
        $remainderSize = 0;

        for ($i = 0; $i < $dataSize; $i++) {
            $b = ord($data[$i]);
            $remainder = ($remainder << 8) | $b;
            $remainderSize += 8;
            while ($remainderSize > 4) {
                $remainderSize -= 5;
                $c = $remainder & (self::BITS_5_RIGHT << $remainderSize);
                $c >>= $remainderSize;
                $res .= self::$CHARS[$c];
            }
        }
        if ($remainderSize > 0) {
            // remainderSize < 5:
            $remainder <<= (5 - $remainderSize);
            $c = $remainder & self::BITS_5_RIGHT;
            $res .= self::$CHARS[$c];
        }

        return ($res);
    }

    public static function b32_decode($data)
    {
        $data = strtoupper($data);
        $dataSize = strlen($data);
        $buf = 0;
        $bufSize = 0;
        $res = '';

        for ($i = 0; $i < $dataSize; $i++) {
            $c = $data[$i];
            $b = strpos(self::$CHARS, $c);
            if ($b === false) {
                throw new \Exception('Encoded string is invalid, it contains unknown char #'.ord($c));
            }
            $buf = ($buf << 5) | $b;
            $bufSize += 5;
            if ($bufSize > 7) {
                $bufSize -= 8;
                $b = ($buf & (0xff << $bufSize)) >> $bufSize;
                $res .= chr($b);
            }
        }

        return ($res);
    }

    public function randomSecret($length = 32)
    {
        $CHARS  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
        $source = '';

        // Valid secret length are 80 to 640 bits
        if ($length < 16 || $length > 128) {
            throw new Exception('Bad secret length');
        }

        for ( $i = 0; $i < $length; $i++){
            $source .= $CHARS[rand(0,35)];
        }

        return $this->b32_encode($source);
    }

    public function getCode($secret, $exampleTime = 123123123)
    {
        $time       = isset($exampleTime) ? $exampleTime : time(); 
        $interval   = intval( $time / 30);
        $secretkey  = $this->b32_decode($secret);

        $time       = chr(0).chr(0).chr(0).chr(0).pack('N*', $interval);
        $hash       = hash_hmac('SHA1', $time, $secretkey, true);
        $offset     = ord(substr($hash, -1)) & 0x0F;
        $hashpart   = substr($hash, $offset, 4);

        $value  = unpack('N', $hashpart);
        $value  = $value[1];
        $value  = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->length);

        return str_pad($value % $modulo, $this->length, '0', STR_PAD_LEFT);
    }

    public function getQR($name, $secret, $title = null, $params = [])
    {
        $width  = !empty($params['width']) && (int) $params['width'] > 0 ? (int) $params['width'] : 200;
        $height = !empty($params['height']) && (int) $params['height'] > 0 ? (int) $params['height'] : 200;
        $level  = !empty($params['level']) && array_search($params['level'], ['L', 'M', 'Q', 'H']) !== false ? $params['level'] : 'M';

        $urlencoded = urlencode('otpauth://totp/'.$name.'?secret='.$secret.'');
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer='.urlencode($title));
        }

        return 'https://chart.googleapis.com/chart?chs='.$width.'x'.$height.'&chld='.$level.'|0&cht=qr&chl='.$urlencoded.'';
    }
}