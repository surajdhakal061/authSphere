package com.suraj.authsphere.authorization.repository;

import com.suraj.authsphere.authorization.domain.UserRole;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    List<UserRole> findByUserId(UUID userId);

    List<UserRole> findByRoleId(UUID roleId);

    Optional<UserRole> findByUserIdAndRoleId(UUID userId, UUID roleId);

    boolean existsByUserIdAndRoleId(UUID userId, UUID roleId);

    int deleteByUserIdAndRoleId(UUID userId, UUID roleId);

    @Query("SELECT r.id FROM UserRole ur JOIN Role r ON ur.roleId = r.id WHERE ur.userId = ?1")
    List<UUID> findRoleIdsByUserId(UUID userId);
}

