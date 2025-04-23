formprotection.page.Manage = function (config) {
    config = config || {};
    Ext.applyIf(config, {
        components: [
            {
                xtype: 'formprotection-panel-manage',
                renderTo: 'formprotection-panel-manage-div'
            }
        ]
    });
    formprotection.page.Manage.superclass.constructor.call(this, config);
};
Ext.extend(formprotection.page.Manage, MODx.Component);
Ext.reg('formprotection-page-manage', formprotection.page.Manage);
