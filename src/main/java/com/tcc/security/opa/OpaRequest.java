package com.tcc.security.opa;

import com.tcc.security.context.AuthorizationContext;

public class OpaRequest {
    private AuthorizationContext input;

    public AuthorizationContext getInput() {
        return input;
    }

    public void setInput(AuthorizationContext input) {
        this.input = input;
    }
}
