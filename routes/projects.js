const express = require('express');
const { body, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { authenticate, authorize, checkResourceAccess } = require('../middleware/auth');
const { validateCUID, validateOptionalCUID } = require('../utils/validation');

const router = express.Router();
const prisma = new PrismaClient();

// Apply authentication middleware to all routes
router.use(authenticate);

// GET /api/projects - List projects
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, search, organizationId } = req.query;
    const skip = (page - 1) * limit;
    const user = req.user;

    let where = {};

    // Apply role-based filtering
    if (user.role === 'ORGANIZATION_MANAGER') {
      where.organization = {
        managerId: user.id
      };
    } else if (user.role === 'REVIEWER') {
      where.projectReviewers = {
        some: {
          userId: user.id
        }
      };
    }

    if (organizationId) {
      where.organizationId = organizationId;
    }

    if (search) {
      where.name = { contains: search, mode: 'insensitive' };
    }

    const [projects, total] = await Promise.all([
      prisma.project.findMany({
        where,
        skip: parseInt(skip),
        take: parseInt(limit),
        include: {
          organization: {
            select: {
              id: true,
              name: true,
              manager: {
                select: {
                  id: true,
                  firstName: true,
                  lastName: true
                }
              }
            }
          },
          currentTour: {
            select: {
              id: true,
              name: true,
              version: true
            }
          },
          _count: {
            select: {
              tours: true,
              projectReviewers: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.project.count({ where })
    ]);

    res.json({
      success: true,
      data: {
        projects,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit),
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch projects'
    });
  }
});

// GET /api/projects/:id - Get specific project
router.get('/:id', checkResourceAccess('project'), async (req, res) => {
  try {
    const { id } = req.params;

    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        organization: {
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
        },
        tours: {
          include: {
            _count: {
              select: {
                comments: true
              }
            }
          },
          orderBy: { createdAt: 'desc' }
        },
        currentTour: true,
        projectReviewers: {
          include: {
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true
              }
            }
          }
        }
      }
    });

    if (!project) {
      return res.status(404).json({
        success: false,
        message: 'Project not found'
      });
    }

    res.json({
      success: true,
      data: project
    });
  } catch (error) {
    console.error('Get project error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch project'
    });
  }
});

// POST /api/projects - Create new project
router.post('/',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  [
    body('name').trim().isLength({ min: 1 }).withMessage('Project name is required'),
    body('description').optional().trim(),
    validateCUID('organizationId', 'Valid organization ID is required')
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

      const { name, description, organizationId } = req.body;
      const user = req.user;

      // Check if user can create project in this organization
      if (user.role === 'ORGANIZATION_MANAGER') {
        const organization = await prisma.organization.findUnique({
          where: { id: organizationId }
        });

        if (!organization || organization.managerId !== user.id) {
          return res.status(403).json({
            success: false,
            message: 'You can only create projects in organizations you manage'
          });
        }
      }

      const project = await prisma.project.create({
        data: {
          name,
          description,
          organizationId
        },
        include: {
          organization: {
            select: {
              id: true,
              name: true
            }
          }
        }
      });

      res.status(201).json({
        success: true,
        message: 'Project created successfully',
        data: project
      });
    } catch (error) {
      console.error('Create project error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create project'
      });
    }
  }
);

// PUT /api/projects/:id - Update project
router.put('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  checkResourceAccess('project'),
  [
    body('name').optional().trim().isLength({ min: 1 }),
    body('description').optional().trim(),
    body('isActive').optional().isBoolean(),
    validateOptionalCUID('currentTourId', 'Valid tour ID required if provided')
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

      // If setting current tour, verify it belongs to this project
      if (updateData.currentTourId) {
        const tour = await prisma.tour.findUnique({
          where: { id: updateData.currentTourId }
        });

        if (!tour || tour.projectId !== id) {
          return res.status(400).json({
            success: false,
            message: 'Tour does not belong to this project'
          });
        }
      }

      const project = await prisma.project.update({
        where: { id },
        data: updateData,
        include: {
          organization: {
            select: {
              id: true,
              name: true
            }
          },
          currentTour: {
            select: {
              id: true,
              name: true,
              version: true
            }
          }
        }
      });

      res.json({
        success: true,
        message: 'Project updated successfully',
        data: project
      });
    } catch (error) {
      console.error('Update project error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Project not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to update project'
      });
    }
  }
);

// DELETE /api/projects/:id - Delete project
router.delete('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  async (req, res) => {
    try {
      const { id } = req.params;

      await prisma.project.delete({
        where: { id }
      });

      res.json({
        success: true,
        message: 'Project deleted successfully'
      });
    } catch (error) {
      console.error('Delete project error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Project not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to delete project'
      });
    }
  }
);

// POST /api/projects/:id/reviewers - Add reviewer to project
router.post('/:id/reviewers',
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

      // Check if current user can add reviewers to this project
      if (user.role === 'ORGANIZATION_MANAGER') {
        const project = await prisma.project.findUnique({
          where: { id },
          include: {
            organization: true
          }
        });

        if (!project || project.organization.managerId !== user.id) {
          return res.status(403).json({
            success: false,
            message: 'You can only add reviewers to projects in organizations you manage'
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

      // Add reviewer
      const reviewer = await prisma.projectReviewer.create({
        data: {
          userId,
          projectId: id
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
        message: 'Reviewer added successfully',
        data: reviewer
      });
    } catch (error) {
      console.error('Add reviewer error:', error);
      if (error.code === 'P2002') {
        return res.status(400).json({
          success: false,
          message: 'User is already a reviewer for this project'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to add reviewer'
      });
    }
  }
);

// DELETE /api/projects/:id/reviewers/:userId - Remove reviewer from project
router.delete('/:id/reviewers/:userId',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  async (req, res) => {
    try {
      const { id, userId } = req.params;
      const user = req.user;

      // Check if current user can remove reviewers from this project
      if (user.role === 'ORGANIZATION_MANAGER') {
        const project = await prisma.project.findUnique({
          where: { id },
          include: {
            organization: true
          }
        });

        if (!project || project.organization.managerId !== user.id) {
          return res.status(403).json({
            success: false,
            message: 'You can only remove reviewers from projects in organizations you manage'
          });
        }
      }

      await prisma.projectReviewer.delete({
        where: {
          userId_projectId: {
            userId,
            projectId: id
          }
        }
      });

      res.json({
        success: true,
        message: 'Reviewer removed successfully'
      });
    } catch (error) {
      console.error('Remove reviewer error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Reviewer assignment not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to remove reviewer'
      });
    }
  }
);

module.exports = router; 