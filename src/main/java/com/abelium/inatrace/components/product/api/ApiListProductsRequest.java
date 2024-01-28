package com.abelium.inatrace.components.product.api;

import org.springframework.validation.annotation.Validated;

import com.abelium.inatrace.api.ApiPaginatedRequest;

import io.swagger.annotations.ApiParam;

@Validated
public class ApiListProductsRequest extends ApiPaginatedRequest {

	@ApiParam(value = "Product name (start of name)")
	public String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
