const express = require('express');
const { body, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { authenticate, authorize, checkResourceAccess } = require('../middleware/auth');
const { validateCUID } = require('../utils/validation');

const router = express.Router();
const prisma = new PrismaClient();

// Apply authentication middleware to all routes
router.use(authenticate);

// GET /api/tours - List tours
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, search, projectId } = req.query;
    const skip = (page - 1) * limit;
    const user = req.user;

    let where = {};

    // Apply role-based filtering
    if (user.role === 'ORGANIZATION_MANAGER') {
      where.project = {
        organization: {
          managerId: user.id
        }
      };
    } else if (user.role === 'REVIEWER') {
      where.project = {
        projectReviewers: {
          some: {
            userId: user.id
          }
        }
      };
    }

    if (projectId) {
      where.projectId = projectId;
    }

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { version: { contains: search, mode: 'insensitive' } }
      ];
    }

    const [tours, total] = await Promise.all([
      prisma.tour.findMany({
        where,
        skip: parseInt(skip),
        take: parseInt(limit),
        include: {
          project: {
            select: {
              id: true,
              name: true,
              organization: {
                select: {
                  id: true,
                  name: true
                }
              }
            }
          },
          _count: {
            select: {
              comments: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.tour.count({ where })
    ]);

    res.json({
      success: true,
      data: {
        tours,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit),
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get tours error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tours'
    });
  }
});

// GET /api/tours/:id - Get specific tour
router.get('/:id', checkResourceAccess('tour'), async (req, res) => {
  try {
    const { id } = req.params;

    const tour = await prisma.tour.findUnique({
      where: { id },
      include: {
        project: {
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
            }
          }
        },
        comments: {
          include: {
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true
              }
            },
            replies: {
              include: {
                user: {
                  select: {
                    id: true,
                    firstName: true,
                    lastName: true
                  }
                }
              }
            }
          },
          where: {
            parentId: null // Only top-level comments
          },
          orderBy: { createdAt: 'desc' }
        }
      }
    });

    if (!tour) {
      return res.status(404).json({
        success: false,
        message: 'Tour not found'
      });
    }

    res.json({
      success: true,
      data: tour
    });
  } catch (error) {
    console.error('Get tour error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tour'
    });
  }
});

// POST /api/tours - Create new tour
router.post('/',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  [
    body('name').trim().isLength({ min: 1 }).withMessage('Tour name is required'),
    body('version').trim().isLength({ min: 1 }).withMessage('Tour version is required'),
    body('description').optional().trim(),
    body('data').optional(),
    validateCUID('projectId', 'Valid project ID is required')
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

      const { name, version, description, data, projectId } = req.body;

      // Verify project exists
      const project = await prisma.project.findUnique({
        where: { id: projectId }
      });

      if (!project) {
        return res.status(400).json({
          success: false,
          message: 'Project not found'
        });
      }

      const tour = await prisma.tour.create({
        data: {
          name,
          version,
          description,
          data,
          projectId
        },
        include: {
          project: {
            select: {
              id: true,
              name: true,
              organization: {
                select: {
                  id: true,
                  name: true
                }
              }
            }
          }
        }
      });

      res.status(201).json({
        success: true,
        message: 'Tour created successfully',
        data: tour
      });
    } catch (error) {
      console.error('Create tour error:', error);
      if (error.code === 'P2002') {
        return res.status(400).json({
          success: false,
          message: 'A tour with this version already exists for this project'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to create tour'
      });
    }
  }
);

// PUT /api/tours/:id - Update tour
router.put('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  checkResourceAccess('tour'),
  [
    body('name').optional().trim().isLength({ min: 1 }),
    body('version').optional().trim().isLength({ min: 1 }),
    body('description').optional().trim(),
    body('data').optional(),
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

      const tour = await prisma.tour.update({
        where: { id },
        data: updateData,
        include: {
          project: {
            select: {
              id: true,
              name: true,
              organization: {
                select: {
                  id: true,
                  name: true
                }
              }
            }
          }
        }
      });

      res.json({
        success: true,
        message: 'Tour updated successfully',
        data: tour
      });
    } catch (error) {
      console.error('Update tour error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Tour not found'
        });
      }
      if (error.code === 'P2002') {
        return res.status(400).json({
          success: false,
          message: 'A tour with this version already exists for this project'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to update tour'
      });
    }
  }
);

// DELETE /api/tours/:id - Delete tour
router.delete('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  async (req, res) => {
    try {
      const { id } = req.params;

      // Check if this tour is set as current for any project
      const projectWithCurrentTour = await prisma.project.findFirst({
        where: { currentTourId: id }
      });

      if (projectWithCurrentTour) {
        return res.status(400).json({
          success: false,
          message: 'Cannot delete tour that is set as current tour for a project'
        });
      }

      await prisma.tour.delete({
        where: { id }
      });

      res.json({
        success: true,
        message: 'Tour deleted successfully'
      });
    } catch (error) {
      console.error('Delete tour error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Tour not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to delete tour'
      });
    }
  }
);

module.exports = router; 