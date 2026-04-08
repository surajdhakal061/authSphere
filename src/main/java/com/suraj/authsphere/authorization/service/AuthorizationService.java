package com.suraj.authsphere.authorization.service;

import com.suraj.authsphere.authorization.domain.Permission;
import com.suraj.authsphere.authorization.domain.Role;
import com.suraj.authsphere.authorization.domain.RolePermission;
import com.suraj.authsphere.authorization.domain.UserRole;
import com.suraj.authsphere.authorization.dto.CreatePermissionRequest;
import com.suraj.authsphere.authorization.dto.CreateRoleRequest;
import com.suraj.authsphere.authorization.dto.PermissionResponse;
import com.suraj.authsphere.authorization.dto.RoleResponse;
import com.suraj.authsphere.authorization.dto.UserPermissionsResponse;
import com.suraj.authsphere.authorization.repository.PermissionRepository;
import com.suraj.authsphere.authorization.repository.RolePermissionRepository;
import com.suraj.authsphere.authorization.repository.RoleRepository;
import com.suraj.authsphere.authorization.repository.UserRoleRepository;
import com.suraj.authsphere.audit.domain.AuditEventType;
import com.suraj.authsphere.audit.domain.AuditOutcome;
import com.suraj.authsphere.audit.domain.AuditSeverity;
import com.suraj.authsphere.audit.service.AuditService;
import com.suraj.authsphere.common.exception.BadRequestException;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthorizationService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final AuditService auditService;

    public AuthorizationService(
        RoleRepository roleRepository,
        PermissionRepository permissionRepository,
        UserRoleRepository userRoleRepository,
        RolePermissionRepository rolePermissionRepository,
        AuditService auditService
    ) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.userRoleRepository = userRoleRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.auditService = auditService;
    }

    // ===================== Role Management =====================

    @Transactional
    public RoleResponse createRole(CreateRoleRequest request) {
        if (roleRepository.existsByName(request.name())) {
            throw new BadRequestException("Role with name '" + request.name() + "' already exists");
        }

        Role role = new Role();
        role.setId(UUID.randomUUID());
        role.setName(request.name());
        role.setDescription(request.description());
        role.setSystemRole(false);

        Role saved = roleRepository.save(role);
        auditService.recordSafely(auditService.build(
            AuditEventType.ROLE_CREATED,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            null,
            null,
            "role",
            saved.getId().toString(),
            "create_role",
            "authorization",
            null,
            null,
            "role_name=" + saved.getName()
        ));
        return toRoleResponse(saved, List.of());
    }

    @Transactional(readOnly = true)
    public RoleResponse getRole(UUID roleId) {
        Role role = roleRepository
            .findById(roleId)
            .orElseThrow(() -> new BadRequestException("Role not found"));

        List<PermissionResponse> permissions = getPermissionsForRole(roleId);
        return toRoleResponse(role, permissions);
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> getAllRoles() {
        return roleRepository.findAll().stream().map(role -> {
            List<PermissionResponse> permissions = getPermissionsForRole(role.getId());
            return toRoleResponse(role, permissions);
        }).toList();
    }

    @Transactional
    public RoleResponse updateRole(UUID roleId, CreateRoleRequest request) {
        Role role = roleRepository
            .findById(roleId)
            .orElseThrow(() -> new BadRequestException("Role not found"));

        if (role.isSystemRole()) {
            throw new BadRequestException("Cannot modify system roles");
        }

        if (!role.getName().equals(request.name()) && roleRepository.existsByName(request.name())) {
            throw new BadRequestException("Role with name '" + request.name() + "' already exists");
        }

        role.setName(request.name());
        role.setDescription(request.description());
        Role saved = roleRepository.save(role);
        auditService.recordSafely(auditService.build(
            AuditEventType.ROLE_UPDATED,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            null,
            null,
            "role",
            saved.getId().toString(),
            "update_role",
            "authorization",
            null,
            null,
            "role_name=" + saved.getName()
        ));

        List<PermissionResponse> permissions = getPermissionsForRole(roleId);
        return toRoleResponse(saved, permissions);
    }

    @Transactional
    public void deleteRole(UUID roleId) {
        Role role = roleRepository
            .findById(roleId)
            .orElseThrow(() -> new BadRequestException("Role not found"));

        if (role.isSystemRole()) {
            throw new BadRequestException("Cannot delete system roles");
        }

        roleRepository.delete(role);
        auditService.recordSafely(auditService.build(
            AuditEventType.ROLE_DELETED,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            null,
            null,
            "role",
            role.getId().toString(),
            "delete_role",
            "authorization",
            null,
            null,
            "role_name=" + role.getName()
        ));
    }

    // ===================== Permission Management =====================

    @Transactional
    public PermissionResponse createPermission(CreatePermissionRequest request) {
        if (permissionRepository.existsByCode(request.code())) {
            throw new BadRequestException("Permission with code '" + request.code() + "' already exists");
        }

        Permission permission = new Permission();
        permission.setId(UUID.randomUUID());
        permission.setCode(request.code());
        permission.setDescription(request.description());
        permission.setResource(request.resource());
        permission.setAction(request.action());

        Permission saved = permissionRepository.save(permission);
        auditService.recordSafely(auditService.build(
            AuditEventType.PERMISSION_CREATED,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            null,
            null,
            "permission",
            saved.getId().toString(),
            "create_permission",
            "authorization",
            null,
            null,
            "code=" + saved.getCode()
        ));
        return toPermissionResponse(saved);
    }

    @Transactional(readOnly = true)
    public PermissionResponse getPermission(UUID permissionId) {
        Permission permission = permissionRepository
            .findById(permissionId)
            .orElseThrow(() -> new BadRequestException("Permission not found"));
        return toPermissionResponse(permission);
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> getAllPermissions() {
        return permissionRepository.findAll().stream().map(this::toPermissionResponse).toList();
    }

    @Transactional
    public PermissionResponse updatePermission(UUID permissionId, CreatePermissionRequest request) {
        Permission permission = permissionRepository
            .findById(permissionId)
            .orElseThrow(() -> new BadRequestException("Permission not found"));

        if (!permission.getCode().equals(request.code()) && permissionRepository.existsByCode(request.code())) {
            throw new BadRequestException("Permission with code '" + request.code() + "' already exists");
        }

        permission.setCode(request.code());
        permission.setDescription(request.description());
        permission.setResource(request.resource());
        permission.setAction(request.action());

        Permission saved = permissionRepository.save(permission);
        auditService.recordSafely(auditService.build(
            AuditEventType.PERMISSION_UPDATED,
            AuditOutcome.SUCCESS,
            AuditSeverity.MEDIUM,
            null,
            null,
            "permission",
            saved.getId().toString(),
            "update_permission",
            "authorization",
            null,
            null,
            "code=" + saved.getCode()
        ));
        return toPermissionResponse(saved);
    }

    @Transactional
    public void deletePermission(UUID permissionId) {
        Permission permission = permissionRepository
            .findById(permissionId)
            .orElseThrow(() -> new BadRequestException("Permission not found"));
        permissionRepository.delete(permission);
        auditService.recordSafely(auditService.build(
            AuditEventType.PERMISSION_DELETED,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            null,
            null,
            "permission",
            permission.getId().toString(),
            "delete_permission",
            "authorization",
            null,
            null,
            "code=" + permission.getCode()
        ));
    }

    // ===================== Role Assignment =====================

    @Transactional
    public void assignRoleToUser(UUID userId, UUID roleId) {
        if (!roleRepository.existsById(roleId)) {
            throw new BadRequestException("Role not found");
        }

        if (userRoleRepository.existsByUserIdAndRoleId(userId, roleId)) {
            throw new BadRequestException("User already has this role");
        }

        UserRole userRole = new UserRole();
        userRole.setId(UUID.randomUUID());
        userRole.setUserId(userId);
        userRole.setRoleId(roleId);

        userRoleRepository.save(userRole);
        auditService.recordSafely(auditService.build(
            AuditEventType.ROLE_ASSIGNED_TO_USER,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            null,
            null,
            "user_role",
            userRole.getId().toString(),
            "assign_role",
            "authorization",
            null,
            null,
            "userId=" + userId + ",roleId=" + roleId
        ));
    }

    @Transactional
    public void removeRoleFromUser(UUID userId, UUID roleId) {
        int removed = userRoleRepository.deleteByUserIdAndRoleId(userId, roleId);
        if (removed == 0) {
            throw new BadRequestException("User does not have this role");
        }
        auditService.recordSafely(auditService.build(
            AuditEventType.ROLE_REMOVED_FROM_USER,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            null,
            null,
            "user_role",
            userId + ":" + roleId,
            "remove_role",
            "authorization",
            null,
            null,
            "userId=" + userId + ",roleId=" + roleId
        ));
    }

    // ===================== Permission Assignment =====================

    @Transactional
    public void assignPermissionToRole(UUID roleId, UUID permissionId) {
        if (!roleRepository.existsById(roleId)) {
            throw new BadRequestException("Role not found");
        }

        if (!permissionRepository.existsById(permissionId)) {
            throw new BadRequestException("Permission not found");
        }

        if (rolePermissionRepository.existsByRoleIdAndPermissionId(roleId, permissionId)) {
            throw new BadRequestException("Role already has this permission");
        }

        RolePermission rolePermission = new RolePermission();
        rolePermission.setId(UUID.randomUUID());
        rolePermission.setRoleId(roleId);
        rolePermission.setPermissionId(permissionId);

        rolePermissionRepository.save(rolePermission);
        auditService.recordSafely(auditService.build(
            AuditEventType.PERMISSION_ASSIGNED_TO_ROLE,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            null,
            null,
            "role_permission",
            rolePermission.getId().toString(),
            "assign_permission",
            "authorization",
            null,
            null,
            "roleId=" + roleId + ",permissionId=" + permissionId
        ));
    }

    @Transactional
    public void removePermissionFromRole(UUID roleId, UUID permissionId) {
        int removed = rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permissionId);
        if (removed == 0) {
            throw new BadRequestException("Role does not have this permission");
        }
        auditService.recordSafely(auditService.build(
            AuditEventType.PERMISSION_REMOVED_FROM_ROLE,
            AuditOutcome.SUCCESS,
            AuditSeverity.HIGH,
            null,
            null,
            "role_permission",
            roleId + ":" + permissionId,
            "remove_permission",
            "authorization",
            null,
            null,
            "roleId=" + roleId + ",permissionId=" + permissionId
        ));
    }

    // ===================== Authorization Checks =====================

    @Transactional(readOnly = true)
    public UserPermissionsResponse getUserPermissions(UUID userId) {
        List<String> roles = getUserRoles(userId);
        List<String> permissions = rolePermissionRepository.findPermissionCodesByUserId(userId);

        return new UserPermissionsResponse(userId, roles, permissions);
    }

    @Transactional(readOnly = true)
    public boolean hasPermission(UUID userId, String permissionCode) {
        List<String> permissions = rolePermissionRepository.findPermissionCodesByUserId(userId);
        return permissions.contains(permissionCode);
    }

    @Transactional(readOnly = true)
    public boolean hasAnyPermission(UUID userId, List<String> permissionCodes) {
        List<String> userPermissions = rolePermissionRepository.findPermissionCodesByUserId(userId);
        return permissionCodes.stream().anyMatch(userPermissions::contains);
    }

    @Transactional(readOnly = true)
    public boolean hasAllPermissions(UUID userId, List<String> permissionCodes) {
        List<String> userPermissions = rolePermissionRepository.findPermissionCodesByUserId(userId);
        return userPermissions.containsAll(permissionCodes);
    }

    @Transactional(readOnly = true)
    public boolean hasRole(UUID userId, String roleName) {
        List<String> roles = getUserRoles(userId);
        return roles.contains(roleName);
    }

    // ===================== Helper Methods =====================

    private List<String> getUserRoles(UUID userId) {
        return userRoleRepository.findByUserId(userId).stream()
            .map(UserRole::getRoleId)
            .map(roleId -> roleRepository.findById(roleId).map(Role::getName).orElse(null))
            .filter(java.util.Objects::nonNull)
            .toList();
    }

    private List<PermissionResponse> getPermissionsForRole(UUID roleId) {
        return rolePermissionRepository.findByRoleId(roleId).stream()
            .map(RolePermission::getPermissionId)
            .map(permissionId -> permissionRepository.findById(permissionId).map(this::toPermissionResponse).orElse(null))
            .filter(java.util.Objects::nonNull)
            .toList();
    }

    private RoleResponse toRoleResponse(Role role, List<PermissionResponse> permissions) {
        return new RoleResponse(
            role.getId(),
            role.getName(),
            role.getDescription(),
            role.isSystemRole(),
            permissions,
            role.getCreatedAt(),
            role.getUpdatedAt()
        );
    }

    private PermissionResponse toPermissionResponse(Permission permission) {
        return new PermissionResponse(
            permission.getId(),
            permission.getCode(),
            permission.getDescription(),
            permission.getResource(),
            permission.getAction(),
            permission.getCreatedAt(),
            permission.getUpdatedAt()
        );
    }
}

