--TEST--
Child class of OAuth cannot access its own attributes
--FILE--
<?php

class Foo extends OAuth
{
    protected $foo = 'bar';

    public function getFoo()
    {
        return $this->foo;
    }
}

$foo = new Foo('key', 'secret');
var_dump($foo->getFoo());

?>
--EXPECTF--
string(3) "bar"
