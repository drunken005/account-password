const Parameter = require('parameter');
const parameter = new Parameter();
const _ = require('lodash');

const check = function (data, rule) {
    let errors = parameter.validate(rule, data);
    if (!errors || !errors.length) {
        return;
    }

    errors = _.map(errors, ({message, code, field}) => {
        return `"${field}" ${message}`;
    });

    throw new Error('parameter error: ' + errors.join(', '));
};

module.exports = check;