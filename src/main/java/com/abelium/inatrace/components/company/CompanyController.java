package com.abelium.inatrace.components.company;

import com.abelium.inatrace.api.*;
import com.abelium.inatrace.api.errors.ApiException;
import com.abelium.inatrace.components.common.api.ApiUserCustomerImportResponse;
import com.abelium.inatrace.components.company.api.*;
import com.abelium.inatrace.components.company.types.CompanyAction;
import com.abelium.inatrace.components.product.api.ApiListCustomersRequest;
import com.abelium.inatrace.components.product.api.ApiProductType;
import com.abelium.inatrace.components.value_chain.api.ApiValueChain;
import com.abelium.inatrace.security.service.CustomUserDetails;
import com.abelium.inatrace.types.Language;
import com.abelium.inatrace.types.UserCustomerType;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/company")
public class CompanyController {

    protected final Logger logger = LoggerFactory.getLogger(CompanyController.class);

	private final CompanyService companyService;

	@Autowired
	public CompanyController(CompanyService companyService) {
		this.companyService = companyService;
	}

	@PostMapping(value = "/create")
    @PreAuthorize("hasAnyAuthority('SYSTEM_ADMIN', 'REGIONAL_ADMIN')")
    @ApiOperation(value = "Create a new company (with the logged-in user as company admin)")
    public ApiResponse<ApiBaseEntity> createCompany(@AuthenticationPrincipal CustomUserDetails authUser, @Valid @RequestBody ApiCompany request) throws ApiException {
		return new ApiResponse<>(companyService.createCompany(authUser.getUserId(), request));
    }
    
    @GetMapping(value = "/list")
    @ApiOperation(value = "Lists all companies for the logged-in user. Sorting: name or default")
    public ApiPaginatedResponse<ApiCompanyListResponse> listCompanies(@AuthenticationPrincipal CustomUserDetails authUser, @Valid ApiListCompaniesRequest request) {
        ApiPaginatedResponse<ApiCompanyListResponse> response = new ApiPaginatedResponse<>(companyService.listUserCompanies(authUser.getUserId(), request));
        logger.info(authUser.getUserId().toString());
        try {
            // Create an ObjectMapper
            ObjectMapper objectMapper = new ObjectMapper();

            // Convert the response object to a JSON string
            String jsonResponse = objectMapper.writeValueAsString(response);

            // Log the JSON response
            logger.info(jsonResponse);

            // Return the original response
            return response;
        } catch (Exception e) {
            // Handle exceptions during JSON conversion
            logger.error("Error converting response to JSON", e);
            return null; // or throw an exception
        }
    }
    
    @GetMapping(value = "/admin/list")
    @PreAuthorize("hasAuthority('SYSTEM_ADMIN')")
    @ApiOperation(value = "Lists all companies. Must be admin. Sorting: name or default")
    public ApiPaginatedResponse<ApiCompanyListResponse> listCompaniesAdmin(@Valid ApiListCompaniesRequest request) {
    	return new ApiPaginatedResponse<>(companyService.listCompanies(request));
    }    
    
    @GetMapping(value = "/profile/{id}")
    @ApiOperation(value = "Get all info about a company")
    public ApiResponse<ApiCompanyGet> getCompany(@AuthenticationPrincipal CustomUserDetails authUser, 
    		@Valid @ApiParam(value = "Record id", required = true) @PathVariable("id") Long id,
    		@Valid @ApiParam(value = "language") @RequestParam(value = "language", defaultValue = "EN") String language) throws ApiException {
    	return new ApiResponse<>(companyService.getCompany(authUser, id, Language.valueOf(language)));
    }

    @GetMapping(value = "/profile/{id}/name")
    @ApiOperation(value = "Get the company name and abbreviation")
    public ApiResponse<ApiCompanyName> getCompanyName(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Record id", required = true) @PathVariable("id") Long id) throws ApiException {
        return new ApiResponse<>(companyService.getCompanyName(authUser, id));
    }

	@GetMapping("/profile/{id}/users")
	@ApiOperation("Get all user for the company with the provided ID")
	public ApiResponse<List<ApiCompanyUser>> getCompanyUsers(
			@Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long id,
            @AuthenticationPrincipal CustomUserDetails authUser) throws ApiException {

		return new ApiResponse<>(companyService.getCompanyUsers(id, authUser));
	}

    @PutMapping(value = "/profile")
    @ApiOperation(value = "Update company data")
    public ApiDefaultResponse updateCompany(@AuthenticationPrincipal CustomUserDetails authUser, @Valid @RequestBody ApiCompanyUpdate company) throws ApiException {
    	companyService.updateCompany(authUser, company);
    	return new ApiDefaultResponse();
    }
    
    @PostMapping(value = "/execute/{action}")
    @ApiOperation(value = "Execute company action. Must be an Company admin, System admin or Regional admin enrolled in this company")
    public ApiDefaultResponse executeAction(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @RequestBody ApiCompanyActionRequest request,
    		@Valid @PathVariable(value = "action") CompanyAction action) throws ApiException {
        companyService.executeAction(authUser, request, action);
        return new ApiDefaultResponse();
    }

    @GetMapping(value = "/userCustomers/{id}")
    @ApiOperation(value = "Get user customer by id")
    public ApiResponse<ApiUserCustomer> getUserCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "User customer ID", required = true) @PathVariable("id") Long id,
            @RequestHeader(value = "language", defaultValue = "EN", required = false) Language language) throws ApiException {

        return new ApiResponse<>(companyService.getUserCustomer(id, authUser, language));
    }

    @GetMapping(value = "/userCustomers/{companyId}/{type}")
    @ApiOperation(value = "Get list of user customers for given company ID and type")
    public ApiPaginatedResponse<ApiUserCustomer> getUserCustomersForCompanyAndType(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("companyId") Long companyId,
            @Valid @ApiParam(value = "Type of user customer (collector, farmer)") @PathVariable("type") UserCustomerType type,
            @RequestHeader(value = "language", defaultValue = "EN", required = false) Language language,
            @Valid ApiListFarmersRequest request) throws ApiException {

        return new ApiPaginatedResponse<>(companyService.getUserCustomersForCompanyAndType(companyId, type, request,
                authUser, language));
    }

    @PostMapping(value = "/userCustomers/add/{companyId}")
    @ApiOperation(value = "Add new user customer for given company ID")
    public ApiResponse<ApiUserCustomer> addUserCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("companyId") Long companyId,
            @RequestHeader(value = "language", defaultValue = "EN", required = false) Language language,
            @Valid @RequestBody ApiUserCustomer request
    ) throws ApiException {
        return new ApiResponse<>(companyService.addUserCustomer(companyId, request, authUser, language));
    }

    @PutMapping(value = "/userCustomers/edit")
    @ApiOperation(value = "Update user customer with given ID")
    public ApiResponse<ApiUserCustomer> updateUserCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @RequestHeader(value = "language", defaultValue = "EN", required = false) Language language,
            @Valid @RequestBody ApiUserCustomer request
    ) throws ApiException {
        return new ApiResponse<>(companyService.updateUserCustomer(request, authUser, language));
    }

    @DeleteMapping(value = "/userCustomers/{id}")
    @ApiOperation(value = "Delete user customer with given id")
    public ApiDefaultResponse deleteUserCustomer(
            @Valid @ApiParam(value = "User customer ID", required = true) @PathVariable("id") Long id,
            @AuthenticationPrincipal CustomUserDetails authUser) throws ApiException {
        companyService.deleteUserCustomer(id, authUser);
        return new ApiDefaultResponse();
    }

    @GetMapping(value = "/companyCustomers/list/{companyId}")
    @ApiOperation(value = "List company customers for company")
    public ApiPaginatedResponse<ApiCompanyCustomer> getCompanyCustomersList(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company id", required = true) @PathVariable("companyId") Long companyId,
            @Valid ApiListCustomersRequest request) throws ApiException {
        return new ApiPaginatedResponse<>(companyService.listCompanyCustomers(authUser, companyId, request));
    }

    @GetMapping(value = "/companyCustomers/{id}")
    @ApiOperation(value = "Get company customer by ID")
    public ApiResponse<ApiCompanyCustomer> getCompanyCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company customer ID", required = true) @PathVariable("id") Long companyCustomerId
    ) throws ApiException {
        return new ApiResponse<>(companyService.getCompanyCustomer(companyCustomerId, authUser));
    }

    @PostMapping(value = "/companyCustomers")
    @ApiOperation(value = "Create company customer")
    public ApiResponse<ApiCompanyCustomer> createCompanyCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @RequestBody ApiCompanyCustomer apiCompanyCustomer) throws ApiException {
        return new ApiResponse<>(companyService.createCompanyCustomer(apiCompanyCustomer, authUser));
    }

    @PutMapping(value = "/companyCustomers")
    @ApiOperation(value = "Update company customer")
    public ApiResponse<ApiCompanyCustomer> updateCompanyCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @RequestBody ApiCompanyCustomer apiCompanyCustomer) throws ApiException {
        return new ApiResponse<>(companyService.updateCompanyCustomer(apiCompanyCustomer, authUser));
    }

    @DeleteMapping(value = "/companyCustomers/{id}")
    @ApiOperation(value = "Delete company customer with ID")
    public ApiDefaultResponse deleteCompanyCustomer(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company customer ID", required = true) @PathVariable("id") Long id) throws ApiException {
        companyService.deleteCompanyCustomer(id, authUser);
        return new ApiDefaultResponse();
    }

    @GetMapping(value = "/associations/{id}")
    @ApiOperation(value = "Get list of associations for the selected company with given ID")
    public ApiPaginatedResponse<ApiCompanyListResponse> getAssociations(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long id,
            @Valid ApiPaginatedRequest request) throws ApiException {
        return new ApiPaginatedResponse<>(companyService.getAssociations(id, request, authUser));
    }

    @GetMapping(value = "/{id}/connected-companies")
    @ApiOperation(value = "Get list of connected companies for the company with the given ID")
    public ApiPaginatedResponse<ApiCompanyListResponse> getConnectedCompanies(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long id,
            @Valid ApiPaginatedRequest request) throws ApiException {
        return new ApiPaginatedResponse<>(companyService.getConnectedCompanies(id, request, authUser));
    }

    @PostMapping(value = "/userCustomers/import/farmers/{companyId}/{documentId}")
    @PreAuthorize("hasAnyAuthority('SYSTEM_ADMIN', 'REGIONAL_ADMIN')")
    @ApiOperation(value = "Upload .xls or .xlsx spreadsheet of farmers to import into DB")
    public ApiUserCustomerImportResponse importFarmersSpreadsheet(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("companyId") Long companyId,
            @Valid @ApiParam(value = "Document ID", required = true) @PathVariable("documentId") Long documentId,
            @RequestHeader(value = "language", defaultValue = "EN", required = false) Language language) throws ApiException {
        return companyService.importFarmersSpreadsheet(companyId, documentId, authUser, language);
    }

    @GetMapping(value = "/{id}/value-chains")
    @ApiOperation(value = "Get list of value chains for the company with the given ID")
    public ApiPaginatedResponse<ApiValueChain> getCompanyValueChains(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long id,
            @Valid ApiPaginatedRequest request) throws ApiException {
        return new ApiPaginatedResponse<>(companyService.getCompanyValueChainList(id, request, authUser));
    }

    @GetMapping(value = "/{id}/product-types")
    @ApiOperation(value = "Get list of product types for the company with the given ID")
    public ApiPaginatedResponse<ApiProductType> getCompanyProductTypes(
            @AuthenticationPrincipal CustomUserDetails authUser,
            @Valid @ApiParam(value = "Company ID", required = true) @PathVariable("id") Long id,
            @RequestHeader(value = "language", defaultValue = "EN", required = false) Language language,
            @Valid ApiPaginatedRequest request) throws ApiException {
        return new ApiPaginatedResponse<>(companyService.getCompanyProductTypesList(id, request, authUser, language));
    }

}
