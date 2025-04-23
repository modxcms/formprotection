var FormProtection = function (config) {
    config = config || {};
    FormProtection.superclass.constructor.call(this, config);
};
Ext.extend(FormProtection, Ext.Component, {

    page: {},
    window: {},
    grid: {},
    tree: {},
    panel: {},
    combo: {},
    field: {},
    config: {},

});
Ext.reg('formprotection', FormProtection);
formprotection = new FormProtection();
