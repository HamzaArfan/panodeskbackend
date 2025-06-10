const express = require('express');
const { body, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { authenticate, authorize, checkResourceAccess } = require('../middleware/auth');
const { validateCUID, validateOptionalCUID } = require('../utils/validation');

const router = express.Router();
const prisma = new PrismaClient();

// Apply authentication middleware to all routes
router.use(authenticate);

// GET /api/organizations - List organizations
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const skip = (page - 1) * limit;
    const user = req.user;

    let where = {};

    // Apply role-based filtering
    if (user.role === 'ORGANIZATION_MANAGER') {
      where.managerId = user.id;
    } else if (user.role === 'REVIEWER') {
      // Reviewers can only see organizations they're members of
      where.members = {
        some: {
          userId: user.id
        }
      };
    }
    // SUPER_ADMIN and SYSTEM_USER can see all organizations

    if (search) {
      where.name = { contains: search, mode: 'insensitive' };
    }

    const [organizations, total] = await Promise.all([
      prisma.organization.findMany({
        where,
        skip: parseInt(skip),
        take: parseInt(limit),
        include: {
          manager: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          _count: {
            select: {
              members: true,
              projects: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.organization.count({ where })
    ]);

    res.json({
      success: true,
      data: {
        organizations,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit),
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get organizations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch organizations'
    });
  }
});

// GET /api/organizations/:id - Get specific organization
router.get('/:id', checkResourceAccess('organization'), async (req, res) => {
  try {
    const { id } = req.params;

    const organization = await prisma.organization.findUnique({
      where: { id },
      include: {
        manager: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        members: {
          include: {
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                role: true
              }
            }
          }
        },
        projects: {
          include: {
            currentTour: true,
            _count: {
              select: {
                tours: true,
                projectReviewers: true
              }
            }
          }
        }
      }
    });

    if (!organization) {
      return res.status(404).json({
        success: false,
        message: 'Organization not found'
      });
    }

    res.json({
      success: true,
      data: organization
    });
  } catch (error) {
    console.error('Get organization error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch organization'
    });
  }
});

// POST /api/organizations - Create new organization
router.post('/',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  [
    body('name').trim().isLength({ min: 1 }).withMessage('Organization name is required'),
    body('description').optional().trim(),
    body('website').optional().isURL().withMessage('Website must be a valid URL'),
    validateCUID('managerId', 'Valid manager ID is required')
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

      const { name, description, website, managerId } = req.body;

      // Verify manager exists and has appropriate role
      const manager = await prisma.user.findUnique({
        where: { id: managerId }
      });

      if (!manager) {
        return res.status(400).json({
          success: false,
          message: 'Manager not found'
        });
      }

      if (!['ORGANIZATION_MANAGER', 'SYSTEM_USER', 'SUPER_ADMIN'].includes(manager.role)) {
        return res.status(400).json({
          success: false,
          message: 'User cannot be assigned as organization manager'
        });
      }

      const organization = await prisma.organization.create({
        data: {
          name,
          description,
          website,
          managerId
        },
        include: {
          manager: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        }
      });

      res.status(201).json({
        success: true,
        message: 'Organization created successfully',
        data: organization
      });
    } catch (error) {
      console.error('Create organization error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create organization'
      });
    }
  }
);

// PUT /api/organizations/:id - Update organization
router.put('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  [
    body('name').optional().trim().isLength({ min: 1 }),
    body('description').optional().trim(),
    body('website').optional().custom((value) => {
      // Allow empty string or null, but if provided, must be valid URL
      if (value && value.trim() !== '') {
        // Use a simple URL validation
        try {
          new URL(value);
          return true;
        } catch {
          throw new Error('Website must be a valid URL');
        }
      }
      return true;
    }),
    validateOptionalCUID('managerId', 'Valid manager ID required if provided'),
    body('isActive').optional().isBoolean()
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
      const updateData = req.body;

      // Handle empty website field - convert to null for database
      if ('website' in updateData && updateData.website === '') {
        updateData.website = null;
      }

      // If updating manager, verify they exist and have appropriate role
      if (updateData.managerId) {
        const manager = await prisma.user.findUnique({
          where: { id: updateData.managerId }
        });

        if (!manager) {
          return res.status(400).json({
            success: false,
            message: 'Manager not found'
          });
        }

        if (!['ORGANIZATION_MANAGER', 'SYSTEM_USER', 'SUPER_ADMIN'].includes(manager.role)) {
          return res.status(400).json({
            success: false,
            message: 'User cannot be assigned as organization manager'
          });
        }
      }

      const organization = await prisma.organization.update({
        where: { id },
        data: updateData,
        include: {
          manager: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        }
      });

      res.json({
        success: true,
        message: 'Organization updated successfully',
        data: organization
      });
    } catch (error) {
      console.error('Update organization error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Organization not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to update organization'
      });
    }
  }
);

// DELETE /api/organizations/:id - Delete organization
router.delete('/:id', authorize(['SUPER_ADMIN', 'SYSTEM_USER']), async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.organization.delete({
      where: { id }
    });

    res.json({
      success: true,
      message: 'Organization deleted successfully'
    });
  } catch (error) {
    console.error('Delete organization error:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Organization not found'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to delete organization'
    });
  }
});

// POST /api/organizations/:id/members - Add member to organization
router.post('/:id/members',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  [
    validateCUID('userId', 'Valid user ID is required')
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
      const { userId } = req.body;
      const user = req.user;

      // Check if current user can add members to this organization
      if (user.role === 'ORGANIZATION_MANAGER') {
        const organization = await prisma.organization.findUnique({
          where: { id }
        });

        if (!organization || organization.managerId !== user.id) {
          return res.status(403).json({
            success: false,
            message: 'You can only add members to organizations you manage'
          });
        }
      }

      // Verify user exists
      const targetUser = await prisma.user.findUnique({
        where: { id: userId }
      });

      if (!targetUser) {
        return res.status(400).json({
          success: false,
          message: 'User not found'
        });
      }

      // Add member
      const membership = await prisma.organizationMember.create({
        data: {
          userId,
          organizationId: id
        },
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
              role: true
            }
          }
        }
      });

      res.status(201).json({
        success: true,
        message: 'Member added successfully',
        data: membership
      });
    } catch (error) {
      console.error('Add member error:', error);
      if (error.code === 'P2002') {
        return res.status(400).json({
          success: false,
          message: 'User is already a member of this organization'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to add member'
      });
    }
  }
);

// DELETE /api/organizations/:id/members/:userId - Remove member from organization
router.delete('/:id/members/:userId',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  async (req, res) => {
    try {
      const { id, userId } = req.params;
      const user = req.user;

      // Check if current user can remove members from this organization
      if (user.role === 'ORGANIZATION_MANAGER') {
        const organization = await prisma.organization.findUnique({
          where: { id }
        });

        if (!organization || organization.managerId !== user.id) {
          return res.status(403).json({
            success: false,
            message: 'You can only remove members from organizations you manage'
          });
        }
      }

      await prisma.organizationMember.delete({
        where: {
          userId_organizationId: {
            userId,
            organizationId: id
          }
        }
      });

      res.json({
        success: true,
        message: 'Member removed successfully'
      });
    } catch (error) {
      console.error('Remove member error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Membership not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to remove member'
      });
    }
  }
);

module.exports = router; 