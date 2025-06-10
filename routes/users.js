const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();
const prisma = new PrismaClient();

// Apply authentication middleware to all routes
router.use(authenticate);

// Helper function to check if user can perform action on target role
const canManageUserRole = (currentUserRole, targetUserRole) => {
  // Super admin can manage everyone
  if (currentUserRole === 'SUPER_ADMIN') {
    return true;
  }
  
  // System user cannot manage super admins
  if (currentUserRole === 'SYSTEM_USER' && targetUserRole === 'SUPER_ADMIN') {
    return false;
  }
  
  // System user can manage system users and below
  if (currentUserRole === 'SYSTEM_USER') {
    return ['SYSTEM_USER', 'ORGANIZATION_MANAGER', 'REVIEWER'].includes(targetUserRole);
  }
  
  return false;
};

// GET /api/users - List all users (System User only)
router.get('/', authorize(['SUPER_ADMIN', 'SYSTEM_USER']), async (req, res) => {
  try {
    const { page = 1, limit = 10, search, role } = req.query;
    const skip = (page - 1) * limit;

    const where = {};
    
    // System users cannot see super admins
    if (req.user.role === 'SYSTEM_USER') {
      where.role = {
        not: 'SUPER_ADMIN'
      };
    }
    
    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } }
      ];
    }
    if (role && req.user.role === 'SUPER_ADMIN') {
      where.role = role;
    } else if (role && req.user.role === 'SYSTEM_USER' && role !== 'SUPER_ADMIN') {
      where.role = role;
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip: parseInt(skip),
        take: parseInt(limit),
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isActive: true,
          emailVerified: true,
          createdAt: true,
          updatedAt: true,
          _count: {
            select: {
              organizationMemberships: true,
              managedOrganizations: true,
              projectReviewers: true,
              comments: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.user.count({ where })
    ]);

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit),
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});

// GET /api/users/:id - Get specific user
router.get('/:id', authorize(['SUPER_ADMIN', 'SYSTEM_USER']), async (req, res) => {
  try {
    const { id } = req.params;

    const user = await prisma.user.findUnique({
      where: { id },
      include: {
        organizationMemberships: {
          include: {
            organization: true
          }
        },
        managedOrganizations: true,
        projectReviewers: {
          include: {
            project: {
              include: {
                organization: true
              }
            }
          }
        },
        _count: {
          select: {
            comments: true,
            sentInvitations: true,
            receivedInvitations: true
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if current user can view this user
    if (!canManageUserRole(req.user.role, user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions to view this user'
      });
    }

    // Remove password from response
    const { password, passwordResetToken, emailVerificationToken, ...userWithoutSensitive } = user;

    res.json({
      success: true,
      data: userWithoutSensitive
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user'
    });
  }
});

// POST /api/users - Create new user (System User only)
router.post('/', 
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('firstName').trim().isLength({ min: 1 }),
    body('lastName').trim().isLength({ min: 1 }),
    body('role').isIn(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER', 'REVIEWER'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const { email, password, firstName, lastName, role } = req.body;

      // Check if current user can create user with this role
      if (!canManageUserRole(req.user.role, role)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to create user with this role'
        });
      }

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email }
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User already exists with this email'
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Create user
      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          firstName,
          lastName,
          role,
          emailVerified: true // Admin created users are auto-verified
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isActive: true,
          emailVerified: true,
          createdAt: true
        }
      });

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: user
      });
    } catch (error) {
      console.error('Create user error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create user'
      });
    }
  }
);

// PUT /api/users/:id - Update user (System User only)
router.put('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  [
    body('email').optional().isEmail().normalizeEmail(),
    body('firstName').optional().trim().isLength({ min: 1 }),
    body('lastName').optional().trim().isLength({ min: 1 }),
    body('role').optional().isIn(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER', 'REVIEWER']),
    body('isActive').optional().isBoolean(),
    body('password').optional().isLength({ min: 6 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const { id } = req.params;
      const { password, role, ...updateData } = req.body;

      // First, get the target user to check their current role
      const targetUser = await prisma.user.findUnique({
        where: { id },
        select: { role: true }
      });

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Check if current user can update this user
      if (!canManageUserRole(req.user.role, targetUser.role)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to update this user'
        });
      }

      // If role is being changed, check if current user can assign the new role
      if (role && !canManageUserRole(req.user.role, role)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to assign this role'
        });
      }

      // Add role to update data if provided
      if (role) {
        updateData.role = role;
      }

      // Remove sensitive fields from update data
      delete updateData.passwordResetToken;
      delete updateData.emailVerificationToken;

      // Handle password update if provided
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 12);
        updateData.password = hashedPassword;
      }

      const user = await prisma.user.update({
        where: { id },
        data: updateData,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isActive: true,
          emailVerified: true,
          updatedAt: true
        }
      });

      res.json({
        success: true,
        message: 'User updated successfully',
        data: user
      });
    } catch (error) {
      console.error('Update user error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to update user'
      });
    }
  }
);

// DELETE /api/users/:id - Delete user (System User only)
router.delete('/:id', authorize(['SUPER_ADMIN', 'SYSTEM_USER']), async (req, res) => {
  try {
    const { id } = req.params;

    // First, get the target user to check their role
    const targetUser = await prisma.user.findUnique({
      where: { id },
      select: { role: true }
    });

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if current user can delete this user
    if (!canManageUserRole(req.user.role, targetUser.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions to delete this user'
      });
    }

    await prisma.user.delete({
      where: { id }
    });

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to delete user'
    });
  }
});

// GET /api/users/me - Get current user profile
router.get('/me', async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        organizationMemberships: {
          include: {
            organization: true
          }
        },
        managedOrganizations: true,
        projectReviewers: {
          include: {
            project: {
              include: {
                organization: true,
                currentTour: true
              }
            }
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Remove sensitive data
    const { password, passwordResetToken, emailVerificationToken, ...userProfile } = user;

    res.json({
      success: true,
      data: userProfile
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile'
    });
  }
});

// PUT /api/users/me - Update current user profile
router.put('/me',
  [
    body('firstName').optional().trim().isLength({ min: 1 }),
    body('lastName').optional().trim().isLength({ min: 1 }),
    body('email').optional().isEmail().normalizeEmail()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const userId = req.user.id;
      const { firstName, lastName, email } = req.body;

      const updateData = {};
      if (firstName) updateData.firstName = firstName;
      if (lastName) updateData.lastName = lastName;
      if (email) updateData.email = email;

      const user = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          emailVerified: true,
          updatedAt: true
        }
      });

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: user
      });
    } catch (error) {
      console.error('Update profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update profile'
      });
    }
  }
);

module.exports = router; 