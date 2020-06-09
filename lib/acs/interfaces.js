"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var AuthZAction;
(function (AuthZAction) {
    AuthZAction["CREATE"] = "CREATE";
    AuthZAction["READ"] = "READ";
    AuthZAction["MODIFY"] = "MODIFY";
    AuthZAction["DELETE"] = "DELETE";
    AuthZAction["EXECUTE"] = "EXECUTE";
    AuthZAction["DROP"] = "DROP";
    AuthZAction["ALL"] = "*";
})(AuthZAction = exports.AuthZAction || (exports.AuthZAction = {}));
var Decision;
(function (Decision) {
    Decision["PERMIT"] = "PERMIT";
    Decision["DENY"] = "DENY";
    Decision["INDETERMINATE"] = "INDETERMINATE";
})(Decision = exports.Decision || (exports.Decision = {}));
var Effect;
(function (Effect) {
    Effect["PERMIT"] = "PERMIT";
    Effect["DENY"] = "DENY";
    Effect["INDETERMINATE"] = "INDETERMINATE";
})(Effect = exports.Effect || (exports.Effect = {}));
