package com.abelium.inatrace.db.entities.facility;

import com.abelium.inatrace.db.entities.common.Location;

import javax.persistence.Column;
import javax.persistence.Entity;

@Entity
public class FacilityLocation extends Location {

	@Column
	private Boolean isPubliclyVisible;

	public FacilityLocation() {
		super();
	}

	public Boolean getPubliclyVisible() {
		return isPubliclyVisible;
	}

	public void setPubliclyVisible(Boolean publiclyVisible) {
		isPubliclyVisible = publiclyVisible;
	}
}
