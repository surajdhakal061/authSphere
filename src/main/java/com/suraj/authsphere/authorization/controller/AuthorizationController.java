package com.suraj.authsphere.authorization.controller;

import com.suraj.authsphere.authorization.dto.AssignPermissionRequest;
import com.suraj.authsphere.authorization.dto.AssignRoleRequest;
import com.suraj.authsphere.authorization.dto.CreatePermissionRequest;
import com.suraj.authsphere.authorization.dto.CreateRoleRequest;
import com.suraj.authsphere.authorization.dto.PermissionResponse;
import com.suraj.authsphere.authorization.dto.RoleResponse;
import com.suraj.authsphere.authorization.dto.UserPermissionsResponse;
import com.suraj.authsphere.authorization.service.AuthorizationService;
import com.suraj.authsphere.common.error.ApiError;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/authorization")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }


    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    public RoleResponse createRole(@Valid @RequestBody CreateRoleRequest request) {
        return authorizationService.createRole(request);
    }

    @GetMapping("/roles/{roleId}")
    public RoleResponse getRole(@PathVariable UUID roleId) {
        return authorizationService.getRole(roleId);
    }

    @GetMapping("/roles")
    public List<RoleResponse> getAllRoles() {
        return authorizationService.getAllRoles();
    }

    @PutMapping("/roles/{roleId}")
    public RoleResponse updateRole(@PathVariable UUID roleId, @Valid @RequestBody CreateRoleRequest request) {
        return authorizationService.updateRole(roleId, request);
    }

    @DeleteMapping("/roles/{roleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteRole(@PathVariable UUID roleId) {
        authorizationService.deleteRole(roleId);
    }

    // ===================== Permission Management =====================

    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    public PermissionResponse createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        return authorizationService.createPermission(request);
    }

    @GetMapping("/permissions/{permissionId}")
    public PermissionResponse getPermission(@PathVariable UUID permissionId) {
        return authorizationService.getPermission(permissionId);
    }

    @GetMapping("/permissions")
    public List<PermissionResponse> getAllPermissions() {
        return authorizationService.getAllPermissions();
    }

    @PutMapping("/permissions/{permissionId}")
    public PermissionResponse updatePermission(
        @PathVariable UUID permissionId,
        @Valid @RequestBody CreatePermissionRequest request
    ) {
        return authorizationService.updatePermission(permissionId, request);
    }

    @DeleteMapping("/permissions/{permissionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deletePermission(@PathVariable UUID permissionId) {
        authorizationService.deletePermission(permissionId);
    }

    // ===================== Role Assignment =====================

    @PostMapping("/users/assign-role")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<ApiError> assignRoleToUser(@Valid @RequestBody AssignRoleRequest request) {
        authorizationService.assignRoleToUser(request.userId(), request.roleId());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/users/{userId}/roles/{roleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removeRoleFromUser(
        @PathVariable UUID userId,
        @PathVariable UUID roleId
    ) {
        authorizationService.removeRoleFromUser(userId, roleId);
    }

    // ===================== Permission Assignment =====================

    @PostMapping("/roles/assign-permission")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<ApiError> assignPermissionToRole(@Valid @RequestBody AssignPermissionRequest request) {
        authorizationService.assignPermissionToRole(request.roleId(), request.permissionId());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/roles/{roleId}/permissions/{permissionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removePermissionFromRole(
        @PathVariable UUID roleId,
        @PathVariable UUID permissionId
    ) {
        authorizationService.removePermissionFromRole(roleId, permissionId);
    }

    // ===================== Authorization Checks =====================

    @GetMapping("/users/{userId}/permissions")
    public UserPermissionsResponse getUserPermissions(@PathVariable UUID userId) {
        return authorizationService.getUserPermissions(userId);
    }

    @GetMapping("/health")
    public String health() {
        return "authorization-service-up";
    }
}

