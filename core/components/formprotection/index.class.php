<?php
abstract class FormProtectionBaseManagerController extends modExtraManagerController {
    /** @var \FormProtection\FormProtection $formprotection */
    public $formprotection;

    public function initialize(): void
    {
        $this->formprotection = $this->modx->services->get('formprotection');

        $this->addCss($this->formprotection->getOption('cssUrl') . 'mgr.css');
        $this->addJavascript($this->formprotection->getOption('jsUrl') . 'mgr/formprotection.js');

        $this->addHtml('
            <script type="text/javascript">
                Ext.onReady(function() {
                    formprotection.config = '.$this->modx->toJSON($this->formprotection->config).';
                });
            </script>
        ');

        parent::initialize();
    }

    public function getLanguageTopics(): array
    {
        return array('formprotection:default');
    }

    public function checkPermissions(): bool
    {
        return true;
    }
}
