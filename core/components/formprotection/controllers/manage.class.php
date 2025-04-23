<?php
require_once dirname(dirname(__FILE__)) . '/index.class.php';

class FormProtectionManageManagerController extends FormProtectionBaseManagerController
{

    public function process(array $scriptProperties = []): void
    {
    }

    public function getPageTitle(): string
    {
        return $this->modx->lexicon('formprotection');
    }

    public function loadCustomCssJs(): void
    {
        $this->addLastJavascript($this->formprotection->getOption('jsUrl') . 'mgr/widgets/manage.panel.js');
        $this->addLastJavascript($this->formprotection->getOption('jsUrl') . 'mgr/sections/manage.js');

        $this->addHtml(
            '
            <script type="text/javascript">
                Ext.onReady(function() {
                    MODx.load({ xtype: "formprotection-page-manage"});
                });
            </script>
        '
        );
    }

    public function getTemplateFile(): string
    {
        return $this->formprotection->getOption('templatesPath') . 'manage.tpl';
    }

}
