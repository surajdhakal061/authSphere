package com.suraj.authsphere.authorization.repository;

import com.suraj.authsphere.authorization.domain.RolePermission;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {

    List<RolePermission> findByRoleId(UUID roleId);

    List<RolePermission> findByPermissionId(UUID permissionId);

    Optional<RolePermission> findByRoleIdAndPermissionId(UUID roleId, UUID permissionId);

    boolean existsByRoleIdAndPermissionId(UUID roleId, UUID permissionId);

    int deleteByRoleIdAndPermissionId(UUID roleId, UUID permissionId);

    @Query("""
        SELECT p.id FROM RolePermission rp 
        JOIN Permission p ON rp.permissionId = p.id 
        WHERE rp.roleId IN (
            SELECT roleId FROM UserRole WHERE userId = ?1
        )
        """)
    List<UUID> findPermissionIdsByUserId(UUID userId);

    @Query("""
        SELECT p.code FROM RolePermission rp 
        JOIN Permission p ON rp.permissionId = p.id 
        WHERE rp.roleId IN (
            SELECT roleId FROM UserRole WHERE userId = ?1
        )
        """)
    List<String> findPermissionCodesByUserId(UUID userId);
}

