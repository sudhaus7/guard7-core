<?php


namespace SUDHAUS7\Guard7Core\Interfaces;

interface ConfigurationAdapterInterface
{
    public function getDefaultMethod(): string;
    public function getCryptLibrary(): string;
}
