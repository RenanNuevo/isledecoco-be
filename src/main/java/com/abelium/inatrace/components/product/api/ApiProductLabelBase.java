package com.abelium.inatrace.components.product.api;

import com.abelium.inatrace.api.ApiBaseEntity;
import com.abelium.inatrace.api.types.Lengths;
import com.abelium.inatrace.types.Language;
import com.abelium.inatrace.types.ProductLabelStatus;
import io.swagger.annotations.ApiModelProperty;
import org.hibernate.validator.constraints.Length;
import org.springframework.validation.annotation.Validated;

@Validated
public class ApiProductLabelBase extends ApiBaseEntity {

	@ApiModelProperty(value = "Product id", position = 2)
	public Long productId;
	
	@ApiModelProperty(value = "Product label status", position = 3)
    public ProductLabelStatus status;

	@ApiModelProperty(value = "Product label uuid (for url)", position = 4)
	public String uuid;
	
	@Length(max = Lengths.DEFAULT)
	@ApiModelProperty(value = "label title", position = 5)
	public String title;

	@ApiModelProperty(value = "Label language", position = 6)
	public Language language;

	public Long getProductId() {
		return productId;
	}

	public void setProductId(Long productId) {
		this.productId = productId;
	}

	public ProductLabelStatus getStatus() {
		return status;
	}

	public void setStatus(ProductLabelStatus status) {
		this.status = status;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public Language getLanguage() {
		return language;
	}

	public void setLanguage(Language language) {
		this.language = language;
	}

}
