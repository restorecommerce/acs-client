"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sconfig = require("@restorecommerce/service-config");
// Export cfg Object
exports.cfg = sconfig(process.cwd());
// errors mapped to code and message
exports.errors = exports.cfg.get('errors');
exports.updateConfig = (config) => {
    exports.cfg = config;
};
