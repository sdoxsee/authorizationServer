'use strict';

angular.module('authorizationserverApp')
    .factory('Register', function ($resource) {
        return $resource('api/register', {}, {
        });
    });


