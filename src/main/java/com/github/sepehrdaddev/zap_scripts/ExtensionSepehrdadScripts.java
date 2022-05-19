/*
 * MIT License
 *
 * Copyright (c) 2022 Sepehrdad
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
package com.github.sepehrdaddev.zap_scripts;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.zap.extension.script.ExtensionScript;

/**
 * Sepehrdad Scripts Extension - a packaged version of https://github.com/sepehrdaddev/zap-scripts
 */
public class ExtensionSepehrdadScripts extends ExtensionAdaptor {

    private File scriptDir = new File(Constant.getZapHome(), "sepehrdadscripts");

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);

        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    @Override
    public String getAuthor() {
        return "Sepehrdad";
    }

    @Override
    public String getName() {
        return "ExtensionSepehrdadScripts";
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("sepehrdadscripts.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("sepehrdadscripts.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void postInit() {
        addScripts();
    }

    private void addScripts() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionScript.class)
                .addScriptsFromDir(scriptDir);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionScript.class)
                .removeScriptsFromDir(scriptDir);
    }
}
