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
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;

import java.net.URL;

/**
 * Gets the absolute path for the defined class
 */
public class ResourceLoader {

	/** The class to be used to build the absolute path */
	protected Class<?> anyClass = ResourceLoader.class;

	/**
	 * Empty constructor. Loads path relatively to the {@link ResourceLoader} class directory.
	 */
	public ResourceLoader() {
	}

	/**
	 * It can be used when there is a need to change the class loader.
	 *
	 * @param anyClass
	 *            the base class to be used
	 */
	public ResourceLoader(Class<?> anyClass) {
		this.anyClass = anyClass;
	}

	/**
	 * This method converts the resource path to the absolute path in target folder.
	 *
	 * @param resourcePath
	 *            resource path
	 * @return the absolute of the parent folder
	 */
	public String getAbsoluteResourceFolder(final String resourcePath) throws DSSException {
		final URL uri = anyClass.getResource(resourcePath);
		if (uri == null) {
			return null;
		}
		final String absolutePath = uri.getPath();
		return DSSUtils.decodeURI(absolutePath);
	}

}
