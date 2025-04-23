/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.DSSException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Provider;
import java.io.File;
import java.io.FileWriter;
import java.security.Security;
import java.lang.reflect.Method;


/**
 * Initializes the SunPKCS11 Provider
 */
public final class SunPKCS11Initializer {

	/** The SunPKCS11 class name */
	private static final String SUN_PKCS11_CLASSNAME = "sun.security.pkcs11.SunPKCS11";

	private SunPKCS11Initializer() {
		// empty
	}

	/**
	 * Initializes the provider
	 *
	 * @param configString {@link String} configuration to use
	 * @return {@link Provider}
	 */
	public static Provider getProvider(String configString) {
		// try (ByteArrayInputStream bais = new ByteArrayInputStream(configString.getBytes())) {
		// 	Class<?> sunPkcs11ProviderClass = Class.forName(SUN_PKCS11_CLASSNAME);
		// 	Constructor<?> constructor = sunPkcs11ProviderClass.getConstructor(InputStream.class);
		// 	return (Provider) constructor.newInstance(bais);
		// } catch (Exception e) {
		// 	throw new DSSException("Unable to instantiate PKCS11 (JDK < 9) ", e);
		// }
		try {
			System.out.println("hafzal: Trying to instantiate PKCS11 provider (JDK >= 9)");
			File configFile = File.createTempFile("pkcs11-", ".cfg");
			configFile.deleteOnExit();
			try (FileWriter writer = new FileWriter(configFile)) {
				writer.write(configString);
			}
	
			// Load SunPKCS11 via reflection (not public in Java 9+)
			Class<?> pkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
			Method configureMethod = pkcs11Class.getMethod("configure", String.class);
			Object sunPKCS11Instance = pkcs11Class.getDeclaredConstructor().newInstance();
	
			Provider provider = (Provider) configureMethod.invoke(sunPKCS11Instance, configFile.getAbsolutePath());
			System.out.println("hafzal: PKCS11 provider instantiated successfully");
			return provider;
	
		} catch (Exception e) {
			System.out.println("hafzal: Unable to instantiate PKCS11 provider (JDK >= 9)");
			throw new DSSException("hafzal: Unable to instantiate PKCS11 provider (JDK >= 9)", e);
		}
	}

}
