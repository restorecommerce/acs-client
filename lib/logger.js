"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const logger_1 = require("@restorecommerce/logger");
const config_1 = require("./config");
exports.default = new logger_1.Logger(config_1.cfg.get('logger'));
