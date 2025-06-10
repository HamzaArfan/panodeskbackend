const express = require('express');
const { body, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { authenticate, authorize, checkResourceAccess } = require('../middleware/auth');
const { validateCUID, validateOptionalCUID } = require('../utils/validation');

const router = express.Router();
const prisma = new PrismaClient();

// Apply authentication middleware to all routes
router.use(authenticate);

// GET /api/comments - List comments
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, tourId, parentId } = req.query;
    const skip = (page - 1) * limit;
    const user = req.user;

    let where = {};

    // Apply role-based filtering
    if (user.role === 'ORGANIZATION_MANAGER') {
      where.tour = {
        project: {
          organization: {
            managerId: user.id
          }
        }
      };
    } else if (user.role === 'REVIEWER') {
      where.tour = {
        project: {
          projectReviewers: {
            some: {
              userId: user.id
            }
          }
        }
      };
    }

    if (tourId) {
      where.tourId = tourId;
    }

    if (parentId) {
      where.parentId = parentId;
    } else {
      // Only get top-level comments by default
      where.parentId = null;
    }

    const [comments, total] = await Promise.all([
      prisma.comment.findMany({
        where,
        skip: parseInt(skip),
        take: parseInt(limit),
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          tour: {
            select: {
              id: true,
              name: true,
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
          },
          _count: {
            select: {
              replies: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.comment.count({ where })
    ]);

    res.json({
      success: true,
      data: {
        comments,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit),
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch comments'
    });
  }
});

// GET /api/comments/:id - Get specific comment
router.get('/:id', checkResourceAccess('comment'), async (req, res) => {
  try {
    const { id } = req.params;

    const comment = await prisma.comment.findUnique({
      where: { id },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        tour: {
          include: {
            project: {
              include: {
                organization: {
                  select: {
                    id: true,
                    name: true
                  }
                }
              }
            }
          }
        },
        parent: {
          include: {
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true
              }
            }
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
          },
          orderBy: { createdAt: 'asc' }
        }
      }
    });

    if (!comment) {
      return res.status(404).json({
        success: false,
        message: 'Comment not found'
      });
    }

    res.json({
      success: true,
      data: comment
    });
  } catch (error) {
    console.error('Get comment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch comment'
    });
  }
});

// POST /api/comments - Create new comment
router.post('/',
  [
    body('content').trim().isLength({ min: 1 }).withMessage('Comment content is required'),
    validateCUID('tourId', 'Valid tour ID is required'),
    validateOptionalCUID('parentId', 'Valid parent comment ID required if provided')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        console.error('Validation errors:', errors.array());
        console.error('Request body:', req.body);
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const { content, tourId, parentId } = req.body;
      const user = req.user;

      console.log('Creating comment with data:', { content, tourId, parentId, userId: user.id });

      // Verify tour exists and user has access
      const tour = await prisma.tour.findUnique({
        where: { id: tourId },
        include: {
          project: {
            include: {
              organization: true,
              projectReviewers: true
            }
          }
        }
      });

      if (!tour) {
        return res.status(400).json({
          success: false,
          message: 'Tour not found'
        });
      }

      // Check access to tour
      let hasAccess = false;
      if (user.role === 'SUPER_ADMIN' || user.role === 'SYSTEM_USER') {
        hasAccess = true;
      } else if (user.role === 'ORGANIZATION_MANAGER') {
        hasAccess = tour.project.organization.managerId === user.id;
      } else if (user.role === 'REVIEWER') {
        hasAccess = tour.project.projectReviewers.some(reviewer => reviewer.userId === user.id);
      }

      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          message: 'Access denied to this tour'
        });
      }

      // If replying to a comment, verify parent exists
      if (parentId) {
        const parentComment = await prisma.comment.findUnique({
          where: { id: parentId }
        });

        if (!parentComment || parentComment.tourId !== tourId) {
          return res.status(400).json({
            success: false,
            message: 'Parent comment not found or belongs to different tour'
          });
        }
      }

      const comment = await prisma.comment.create({
        data: {
          content,
          userId: user.id,
          tourId,
          parentId: parentId || null // Ensure empty strings become null
        },
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          tour: {
            select: {
              id: true,
              name: true
            }
          }
        }
      });

      res.status(201).json({
        success: true,
        message: 'Comment created successfully',
        data: comment
      });
    } catch (error) {
      console.error('Create comment error:', error);
      console.error('Request body:', req.body);
      res.status(500).json({
        success: false,
        message: 'Failed to create comment'
      });
    }
  }
);

// PUT /api/comments/:id - Update comment
router.put('/:id',
  [
    body('content').trim().isLength({ min: 1 }).withMessage('Comment content is required')
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
      const { content } = req.body;
      const user = req.user;

      // Get the comment first
      const existingComment = await prisma.comment.findUnique({
        where: { id },
        include: {
          tour: {
            include: {
              project: {
                include: {
                  organization: true
                }
              }
            }
          }
        }
      });

      if (!existingComment) {
        return res.status(404).json({
          success: false,
          message: 'Comment not found'
        });
      }

      // Check permissions: users can edit their own comments, admins can edit any
      let canEdit = false;
      if (user.role === 'SUPER_ADMIN' || user.role === 'SYSTEM_USER') {
        canEdit = true;
      } else if (existingComment.userId === user.id) {
        canEdit = true;
      } else if (user.role === 'ORGANIZATION_MANAGER') {
        canEdit = existingComment.tour.project.organization.managerId === user.id;
      }

      if (!canEdit) {
        return res.status(403).json({
          success: false,
          message: 'You can only edit your own comments'
        });
      }

      const comment = await prisma.comment.update({
        where: { id },
        data: { content },
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          tour: {
            select: {
              id: true,
              name: true
            }
          }
        }
      });

      res.json({
        success: true,
        message: 'Comment updated successfully',
        data: comment
      });
    } catch (error) {
      console.error('Update comment error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update comment'
      });
    }
  }
);

// DELETE /api/comments/:id - Delete comment
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = req.user;

    // Get the comment first
    const existingComment = await prisma.comment.findUnique({
      where: { id },
      include: {
        tour: {
          include: {
            project: {
              include: {
                organization: true
              }
            }
          }
        }
      }
    });

    if (!existingComment) {
      return res.status(404).json({
        success: false,
        message: 'Comment not found'
      });
    }

    // Check permissions: users can delete their own comments, admins can delete any
    let canDelete = false;
    if (user.role === 'SUPER_ADMIN' || user.role === 'SYSTEM_USER') {
      canDelete = true;
    } else if (existingComment.userId === user.id) {
      canDelete = true;
    } else if (user.role === 'ORGANIZATION_MANAGER') {
      canDelete = existingComment.tour.project.organization.managerId === user.id;
    }

    if (!canDelete) {
      return res.status(403).json({
        success: false,
        message: 'You can only delete your own comments'
      });
    }

    await prisma.comment.delete({
      where: { id }
    });

    res.json({
      success: true,
      message: 'Comment deleted successfully'
    });
  } catch (error) {
    console.error('Delete comment error:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Comment not found'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to delete comment'
    });
  }
});

module.exports = router; 