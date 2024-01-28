package com.abelium.inatrace.db.entities.product;

import com.abelium.inatrace.api.types.Lengths;
import com.abelium.inatrace.db.base.BaseEntity;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Entity
public class Responsibility extends BaseEntity {

	/**
	 * labor policies - Briefly describe labor policies you have in place in your company and 
	 * activities you pursue to make them happen (example: women inclusion, no child labor, etc.)
	 */
	@Lob
	private String laborPolicies;
	
	public String getLaborPolicies() {
		return laborPolicies;
	}

	public void setLaborPolicies(String laborPolicies) {
		this.laborPolicies = laborPolicies;
	}

	public Responsibility copy() {
		return new Responsibility();
	}

}
