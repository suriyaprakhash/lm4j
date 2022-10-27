package com.suriya.keychain.core.chain;

import com.suriya.license.io.Info;

import java.util.Map;
import java.util.Set;

public class Storage {

    protected Info info;
    protected Set<String> infoKeyAttributeSet;
    protected Map<String, String> infoKeyAttributeMap;
    protected Map<String, String> headerMap;

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

    public Map<String, String> getHeaderMap() {
        return headerMap;
    }

    public void setHeaderMap(Map<String, String> headerMap) {
        this.headerMap = headerMap;
    }
}
