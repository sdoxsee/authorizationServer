'use strict';

angular.module('authorizationserverApp')
    .controller('LogoutController', function (Auth) {
        Auth.logout();
    });
