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
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;

/**
 * This class is a DTO to transfer required objects to execute extendDocument method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class ExtendDocumentDTO implements Serializable {

	/** Document to extend */
	private RemoteDocument toExtendDocument;

	/** Extension parameters */
	private RemoteSignatureParameters parameters;

	/**
	 * Empty document
	 */
	public ExtendDocumentDTO() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param toExtendDocument {@link RemoteDocument}
	 * @param parameters {@link RemoteSignatureParameters}
	 */
	public ExtendDocumentDTO(RemoteDocument toExtendDocument, RemoteSignatureParameters parameters) {
		this.toExtendDocument = toExtendDocument;
		this.parameters = parameters;
	}

	/**
	 * Gets the document to be extended
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getToExtendDocument() {
		return toExtendDocument;
	}

	/**
	 * Sets the document to be extended
	 *
	 * @param toExtendDocument {@link RemoteDocument}
	 */
	public void setToExtendDocument(RemoteDocument toExtendDocument) {
		this.toExtendDocument = toExtendDocument;
	}

	/**
	 * Gets the extension parameters
	 *
	 * @return {@link RemoteSignatureParameters}
	 */
	public RemoteSignatureParameters getParameters() {
		return parameters;
	}

	/**
	 * Sets the extension parameters
	 *
	 * @param parameters {@link RemoteSignatureParameters}
	 */
	public void setParameters(RemoteSignatureParameters parameters) {
		this.parameters = parameters;
	}

	@Override
	public String toString() {
		return "DataToSignDTO [toExtendDocument=" + toExtendDocument + ", parameters=" + parameters + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((parameters == null) ? 0 : parameters.hashCode());
		result = (prime * result) + ((toExtendDocument == null) ? 0 : toExtendDocument.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ExtendDocumentDTO other = (ExtendDocumentDTO) obj;
		if (parameters == null) {
			if (other.parameters != null) {
				return false;
			}
		} else if (!parameters.equals(other.parameters)) {
			return false;
		}
		if (toExtendDocument == null) {
			if (other.toExtendDocument != null) {
				return false;
			}
		} else if (!toExtendDocument.equals(other.toExtendDocument)) {
			return false;
		}
		return true;
	}

}
