package com.suriya.keychain.core;

import com.suriya.license.io.Info;

import java.util.Map;
import java.util.Set;

public class Base {

    protected Info info;
    protected Set<String> infoKeyAttributeSet;
    protected Map<String, String> infoKeyAttributeMap;

    public Info getInfo() {
        return info;
    }

    public void setInfo(Info info) {
        this.info = info;
    }

    public Set<String> getInfoKeyAttributeSet() {
        return infoKeyAttributeSet;
    }

    public void setInfoKeyAttributeSet(Set<String> infoKeyAttributeSet) {
        this.infoKeyAttributeSet = infoKeyAttributeSet;
    }

    public Map<String, String> getInfoKeyAttributeMap() {
        return infoKeyAttributeMap;
    }

    public void setInfoKeyAttributeMap(Map<String, String> infoKeyAttributeMap) {
        this.infoKeyAttributeMap = infoKeyAttributeMap;
    }
}
