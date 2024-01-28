package com.abelium.inatrace.components.product.api;

import javax.validation.Valid;

import org.hibernate.validator.constraints.Length;
import org.springframework.validation.annotation.Validated;

import com.abelium.inatrace.api.types.Lengths;
import com.abelium.inatrace.components.common.api.ApiDocument;
import io.swagger.annotations.ApiModelProperty;

@Validated
public class ApiProcessDocument {
	
	@Length(max = Lengths.DEFAULT)
	@ApiModelProperty(value = "description of this document", position = 1)
	public String description;
	
	@ApiModelProperty(value = "certificate for this document", position = 2)
	@Valid
	public ApiDocument document;

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
	
	public ApiDocument getDocument() {
		return document;
	}

	public void setDocument(ApiDocument document) {
		this.document = document;
	}
}
