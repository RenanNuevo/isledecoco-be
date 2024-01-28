package com.abelium.inatrace.components.payment;

import com.abelium.inatrace.api.*;
import com.abelium.inatrace.api.errors.ApiException;
import com.abelium.inatrace.components.payment.api.ApiBulkPayment;
import com.abelium.inatrace.components.payment.api.ApiPayment;
import com.abelium.inatrace.db.entities.payment.PaymentStatus;
import com.abelium.inatrace.db.entities.stockorder.enums.PreferredWayOfPayment;
import com.abelium.inatrace.security.service.CustomUserDetails;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDate;

/**
 * REST controller for payment entity.
 *
 * @author Rene Flores, Sunesis d.o.o.
 */
@RestController
@RequestMapping("/chain/payment")
public class PaymentController {

	private final PaymentService paymentService;

	@Autowired
	public PaymentController(PaymentService paymentService) {
		this.paymentService = paymentService;
	}

	@GetMapping("{id}")
	@ApiOperation("Get a single payment with the provided ID.")
	public ApiResponse<ApiPayment> getPayment(
			@AuthenticationPrincipal CustomUserDetails authUser,
			@Valid @ApiParam(value = "Payment ID", required = true) @PathVariable("id") Long id) throws ApiException {
		return new ApiResponse<>(paymentService.getPayment(id, authUser));
	}
	
	@GetMapping("bulk-payment/{id}")
	@ApiOperation("Get a single bulk payment with the provided ID.")
	public ApiResponse<ApiBulkPayment> getBulkPayment(
			@Valid @ApiParam(value = "Bulk payment ID", required = true) @PathVariable("id") Long id,
			@AuthenticationPrincipal CustomUserDetails authUser) throws ApiException {

		return new ApiResponse<>(paymentService.getBulkPayment(id, authUser));
	}

	@GetMapping("list/purchase/{id}")
	@ApiOperation("Get a list of payments by purchase order (stock order) ID.")
	public ApiPaginatedResponse<ApiPayment> listPaymentsByPurchase(
			@AuthenticationPrincipal CustomUserDetails authUser,
			@Valid ApiPaginatedRequest request,
			@Valid @ApiParam(value = "Purchase ID", required = true) @PathVariable("id") Long purchaseId,
			@Valid @ApiParam(value = "Preferred way of payment") @RequestParam(value = "preferredWayOfPayment", required = false) PreferredWayOfPayment preferredWayOfPayment,
			@Valid @ApiParam(value = "Payment status") @RequestParam(value = "paymentStatus", required = false) PaymentStatus paymentStatus,
			@Valid @ApiParam(value = "Production date range start") @RequestParam(value = "productionDateStart", required = false) LocalDate productionDateStart,
			@Valid @ApiParam(value = "Production date range end") @RequestParam(value = "productionDateEnd", required = false) LocalDate productionDateEnd,
			@Valid @ApiParam(value = "Search by farmer name") @RequestParam(value = "query", required = false) String farmerName) throws ApiException {

		return new ApiPaginatedResponse<>(paymentService.getPaymentList(
				request,
				new PaymentQueryRequest(
						null,
						purchaseId,
						preferredWayOfPayment,
						paymentStatus,
						productionDateStart,
						productionDateEnd,
						farmerName,
						null,
						null
				),
				authUser
		));
	}

	@GetMapping("list/company/{id}")
	@ApiOperation("Get a list of payments by company ID.")
	public ApiPaginatedResponse<ApiPayment> listPaymentsByCompany(
			@AuthenticationPrincipal CustomUserDetails authUser,
			@Valid ApiPaginatedRequest request,
			@Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long companyId,
			@Valid @ApiParam(value = "Preferred way of payment") @RequestParam(value = "preferredWayOfPayment", required = false) PreferredWayOfPayment preferredWayOfPayment,
			@Valid @ApiParam(value = "Payment status") @RequestParam(value = "paymentStatus", required = false) PaymentStatus paymentStatus,
			@Valid @ApiParam(value = "Production date range start") @RequestParam(value = "productionDateStart", required = false) LocalDate productionDateStart,
			@Valid @ApiParam(value = "Production date range end") @RequestParam(value = "productionDateEnd", required = false) LocalDate productionDateEnd,
			@Valid @ApiParam(value = "Search by farmer name") @RequestParam(value = "query", required = false) String farmerName,
			@Valid @ApiParam(value = "Search by farmer id") @RequestParam(value = "farmerId", required = false) Long farmerId,
			@Valid @ApiParam(value = "Search by representative of farmer id") @RequestParam(value = "representativeOfRecipientUserCustomerId", required = false) Long representativeOfRecipientUserCustomerId) throws ApiException {

		return new ApiPaginatedResponse<>(paymentService.getPaymentList(
				request,
				new PaymentQueryRequest(
						companyId,
						null,
						preferredWayOfPayment,
						paymentStatus,
						productionDateStart,
						productionDateEnd,
						farmerName,
						farmerId,
						representativeOfRecipientUserCustomerId
				), authUser
		));
	}

	@GetMapping("list/bulk-payment/company/{id}")
	@ApiOperation("Get a list of bulk payments by company ID.")
	public ApiPaginatedResponse<ApiBulkPayment> listBulkPaymentsByCompany(
		@Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long companyId,
		@AuthenticationPrincipal CustomUserDetails authUser,
		@Valid ApiPaginatedRequest request) throws ApiException {

		return new ApiPaginatedResponse<>(paymentService.listBulkPayments(
				request,
				new PaymentQueryRequest(companyId),
				authUser)
		);
	}

	@PutMapping
	@ApiOperation("Create or update payment. If ID is provided, then the entity with the provided ID is updated.")
	public ApiResponse<ApiBaseEntity> createOrUpdatePayment(
			@Valid @RequestBody ApiPayment apiPayment,
			@AuthenticationPrincipal CustomUserDetails authUser) throws ApiException {

		return new ApiResponse<>(paymentService.createOrUpdatePayment(apiPayment, authUser, false));
	}
	
	@PostMapping("bulk-payment")
	@ApiOperation("Create bulk payment.")
	public ApiResponse<ApiBaseEntity> createBulkPayment(
			@Valid @RequestBody ApiBulkPayment apiBulkPayment,
			@AuthenticationPrincipal CustomUserDetails authUser) throws ApiException {

		return new ApiResponse<>(paymentService.createBulkPayment(apiBulkPayment, authUser));
	}

	@DeleteMapping("{id}")
	@ApiOperation("Deletes a payment with the provided ID.")
	public ApiDefaultResponse deletePayment(
			@Valid @ApiParam(value = "Payment ID", required = true) @PathVariable("id") Long id,
			@AuthenticationPrincipal CustomUserDetails authUser) throws ApiException {

		paymentService.deletePayment(id, authUser);
		return new ApiDefaultResponse();
	}

}
